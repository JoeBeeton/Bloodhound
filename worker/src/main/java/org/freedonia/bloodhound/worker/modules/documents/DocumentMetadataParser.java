package org.freedonia.bloodhound.worker.modules.documents;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.poi.hpsf.DocumentSummaryInformation;
import org.apache.poi.hpsf.PropertySetFactory;
import org.apache.poi.hpsf.SummaryInformation;
import org.apache.poi.ooxml.POIXMLProperties;
import org.apache.poi.openxml4j.opc.OPCPackage;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sniffs a document's actual format from its magic bytes (not the URL's file
 * extension, which is only a hint used for link discovery - see
 * DocumentLinkDecisionLogic - and could be wrong or absent) and extracts
 * author/editor metadata via Apache PDFBox (PDF) or Apache POI (both modern
 * OOXML and legacy OLE2 Office formats). Never throws: a malformed,
 * password-protected, or otherwise unparseable document just yields {@link
 * java.util.Optional#empty()}, the same "best-effort, no exception
 * propagation" contract as {@code TechFetcher#fetchWpJson}.
 *
 * <p>Every extracted string field is also scanned for something that looks
 * like an internal filesystem path (a Windows drive path, a UNC share, or a
 * Unix home directory) - author-application metadata (especially a DOCX/PPTX
 * "Template" property, or a legacy .doc's summary info) is a well-known
 * real-world source of exactly this kind of leak, distinct from - and more
 * concretely useful to an attacker than - a bare author name.
 */
final class DocumentMetadataParser {

    private static final Logger log = LoggerFactory.getLogger(DocumentMetadataParser.class);

    private static final List<Pattern> PATH_PATTERNS = List.of(
            Pattern.compile("[A-Za-z]:\\\\(?:[^\\r\\n\"'<>|*?]+\\\\)*[^\\r\\n\"'<>|*?]+"),
            Pattern.compile("\\\\\\\\[^\\s\\\\\"'<>]+(?:\\\\[^\\s\\\\\"'<>]+)+"),
            Pattern.compile("/(?:home|Users|root)/[^\\s\"'<>]+"));

    private DocumentMetadataParser() {}

    static java.util.Optional<DocumentMetadata> parse(String documentUrl, byte[] bytes) {
        try {
            if (isPdf(bytes)) {
                return java.util.Optional.of(parsePdf(documentUrl, bytes));
            }
            if (isOoxmlZip(bytes)) {
                return java.util.Optional.of(parseOoxml(documentUrl, bytes));
            }
            if (isOle2(bytes)) {
                return java.util.Optional.of(parseOle2(documentUrl, bytes));
            }
            return java.util.Optional.empty();
        } catch (Exception e) {
            log.debug("document metadata parse of {} failed: {}", documentUrl, e.getMessage());
            return java.util.Optional.empty();
        }
    }

    private static boolean isPdf(byte[] bytes) {
        return bytes.length >= 5
                && bytes[0] == '%'
                && bytes[1] == 'P'
                && bytes[2] == 'D'
                && bytes[3] == 'F'
                && bytes[4] == '-';
    }

    private static boolean isOoxmlZip(byte[] bytes) {
        return bytes.length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 3 && bytes[3] == 4;
    }

    private static boolean isOle2(byte[] bytes) {
        byte[] magic = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1};
        if (bytes.length < magic.length) {
            return false;
        }
        for (int i = 0; i < magic.length; i++) {
            if (bytes[i] != magic[i]) {
                return false;
            }
        }
        return true;
    }

    private static DocumentMetadata parsePdf(String documentUrl, byte[] bytes) throws Exception {
        try (PDDocument doc = Loader.loadPDF(bytes)) {
            PDDocumentInformation info = doc.getDocumentInformation();
            if (info == null) {
                return empty(documentUrl);
            }
            return build(documentUrl, info.getAuthor(), null, info.getCreator(), null, null, info.getProducer());
        }
    }

    private static DocumentMetadata parseOoxml(String documentUrl, byte[] bytes) throws Exception {
        try (OPCPackage pkg = OPCPackage.open(new ByteArrayInputStream(bytes))) {
            POIXMLProperties props = new POIXMLProperties(pkg);
            var core = props.getCoreProperties();
            var extended = props.getExtendedProperties().getUnderlyingProperties();
            return build(
                    documentUrl,
                    core.getCreator(),
                    core.getLastModifiedByUser(),
                    extended.getApplication(),
                    extended.getCompany(),
                    extended.getManager(),
                    extended.getTemplate());
        }
    }

    /**
     * SummaryInformation/DocumentSummaryInformation are a generic OLE2
     * compound-file convention (a well-known stream name under the root
     * storage), not specific to Word/Excel/PowerPoint - so this reads them
     * directly rather than going through any of POI's format-specific
     * (.doc/.xls/.ppt) text extractors, which would need to already know
     * which of the three this file actually is.
     */
    private static DocumentMetadata parseOle2(String documentUrl, byte[] bytes) throws Exception {
        try (POIFSFileSystem fs = new POIFSFileSystem(new ByteArrayInputStream(bytes))) {
            DirectoryEntry root = fs.getRoot();
            SummaryInformation summary =
                    readPropertySet(root, SummaryInformation.DEFAULT_STREAM_NAME, SummaryInformation.class);
            DocumentSummaryInformation docSummary = readPropertySet(
                    root, DocumentSummaryInformation.DEFAULT_STREAM_NAME, DocumentSummaryInformation.class);
            String author = summary != null ? summary.getAuthor() : null;
            String lastAuthor = summary != null ? summary.getLastAuthor() : null;
            String application = summary != null ? summary.getApplicationName() : null;
            String company = docSummary != null ? docSummary.getCompany() : null;
            String manager = docSummary != null ? docSummary.getManager() : null;
            return build(documentUrl, author, lastAuthor, application, company, manager, null);
        }
    }

    private static <T> T readPropertySet(DirectoryEntry root, String streamName, Class<T> type) {
        try {
            if (!root.hasEntry(streamName)) {
                return null;
            }
            DocumentEntry entry = (DocumentEntry) root.getEntry(streamName);
            try (DocumentInputStream is = new DocumentInputStream(entry)) {
                return type.cast(PropertySetFactory.create(is));
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static DocumentMetadata empty(String documentUrl) {
        return new DocumentMetadata(documentUrl, null, null, null, null, null, List.of());
    }

    private static DocumentMetadata build(
            String documentUrl,
            String author,
            String lastModifiedBy,
            String application,
            String company,
            String manager,
            String template) {
        Set<String> leaked = new LinkedHashSet<>();
        for (String value : List.of(
                nullToEmpty(author),
                nullToEmpty(lastModifiedBy),
                nullToEmpty(application),
                nullToEmpty(company),
                nullToEmpty(manager),
                nullToEmpty(template))) {
            leaked.addAll(findPaths(value));
        }
        return new DocumentMetadata(
                documentUrl,
                blankToNull(author),
                blankToNull(lastModifiedBy),
                blankToNull(application),
                blankToNull(company),
                blankToNull(manager),
                List.copyOf(leaked));
    }

    static List<String> findPaths(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        List<String> matches = new ArrayList<>();
        for (Pattern pattern : PATH_PATTERNS) {
            Matcher m = pattern.matcher(value);
            if (m.find()) {
                matches.add(m.group());
            }
        }
        return matches;
    }

    private static String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
