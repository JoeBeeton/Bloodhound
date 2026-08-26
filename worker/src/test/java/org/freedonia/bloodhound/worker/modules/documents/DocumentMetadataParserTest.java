package org.freedonia.bloodhound.worker.modules.documents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

import java.io.ByteArrayOutputStream;
import java.util.List;
import java.util.Optional;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.xwpf.usermodel.XWPFDocument;
import org.junit.jupiter.api.Test;

/**
 * Generates real documents via PDFBox's/POI's own creation APIs, sets known
 * metadata, then parses the resulting bytes back through
 * DocumentMetadataParser - real document structures, not hand-crafted byte
 * fixtures, exercising the exact same library calls production code path
 * uses.
 */
class DocumentMetadataParserTest {

    private static final String DOC_URL = "https://example.com/files/handbook.pdf";

    @Test
    void pdf_extractsAuthorCreatorProducer() throws Exception {
        byte[] bytes = buildPdf("Jane Doe", "Microsoft Word", "Microsoft: Word for Microsoft 365");
        Optional<DocumentMetadata> result = DocumentMetadataParser.parse(DOC_URL, bytes);
        assertThat(result).isPresent();
        DocumentMetadata metadata = result.get();
        assertThat(metadata.author()).isEqualTo("Jane Doe");
        assertThat(metadata.application()).isEqualTo("Microsoft Word");
        assertThat(metadata.leakedPaths()).isEmpty();
    }

    @Test
    void pdf_noMetadataSet_emptyButPresentResult() throws Exception {
        byte[] bytes;
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new org.apache.pdfbox.pdmodel.PDPage());
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            bytes = out.toByteArray();
        }
        Optional<DocumentMetadata> result = DocumentMetadataParser.parse(DOC_URL, bytes);
        assertThat(result).isPresent();
        assertThat(result.get().hasAnyAuthorInfo()).isFalse();
    }

    @Test
    void docx_extractsCoreAndExtendedProperties() throws Exception {
        byte[] bytes;
        try (XWPFDocument doc = new XWPFDocument()) {
            doc.getProperties().getCoreProperties().setCreator("Jane Doe");
            doc.getProperties().getCoreProperties().setLastModifiedByUser("John Smith");
            var extended = doc.getProperties().getExtendedProperties().getUnderlyingProperties();
            extended.setApplication("Microsoft Office Word");
            extended.setCompany("Example Corp");
            extended.setManager("Jane Manager");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.write(out);
            bytes = out.toByteArray();
        }
        Optional<DocumentMetadata> result =
                DocumentMetadataParser.parse("https://example.com/files/report.docx", bytes);
        assertThat(result).isPresent();
        DocumentMetadata metadata = result.get();
        assertThat(metadata.author()).isEqualTo("Jane Doe");
        assertThat(metadata.lastModifiedBy()).isEqualTo("John Smith");
        assertThat(metadata.application()).isEqualTo("Microsoft Office Word");
        assertThat(metadata.company()).isEqualTo("Example Corp");
        assertThat(metadata.manager()).isEqualTo("Jane Manager");
    }

    @Test
    void docx_templateFieldWithWindowsPath_detectedAsLeak() throws Exception {
        byte[] bytes;
        try (XWPFDocument doc = new XWPFDocument()) {
            doc.getProperties().getCoreProperties().setCreator("Jane Doe");
            var extended = doc.getProperties().getExtendedProperties().getUnderlyingProperties();
            extended.setTemplate("C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.write(out);
            bytes = out.toByteArray();
        }
        Optional<DocumentMetadata> result =
                DocumentMetadataParser.parse("https://example.com/files/report.docx", bytes);
        assertThat(result).isPresent();
        assertThat(result.get().leakedPaths())
                .containsExactly("C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Templates\\Normal.dotm");
    }

    @Test
    void legacyXls_extractsSummaryAndDocSummaryInformation() throws Exception {
        byte[] bytes;
        try (HSSFWorkbook workbook = new HSSFWorkbook()) {
            workbook.createSheet("Sheet1");
            workbook.createInformationProperties();
            workbook.getSummaryInformation().setAuthor("Jane Doe");
            workbook.getSummaryInformation().setApplicationName("Microsoft Excel");
            workbook.getDocumentSummaryInformation().setCompany("Example Corp");
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            workbook.write(out);
            bytes = out.toByteArray();
        }
        Optional<DocumentMetadata> result = DocumentMetadataParser.parse("https://example.com/files/report.xls", bytes);
        assertThat(result).isPresent();
        DocumentMetadata metadata = result.get();
        assertThat(metadata.author()).isEqualTo("Jane Doe");
        assertThat(metadata.application()).isEqualTo("Microsoft Excel");
        assertThat(metadata.company()).isEqualTo("Example Corp");
    }

    @Test
    void garbageBytes_notAnyKnownFormat_emptyOptional() {
        byte[] garbage = "this is not a document".getBytes();
        assertThat(DocumentMetadataParser.parse(DOC_URL, garbage)).isEmpty();
    }

    @Test
    void truncatedPdf_malformed_neverThrows() {
        // PDFBox is deliberately lenient/recovering with corrupt PDFs (mirroring how real PDF
        // readers try to recover), so truncation doesn't reliably produce an empty result - what
        // this actually guards is DocumentMetadataParser#parse never propagating an exception for
        // malformed-but-PDF-shaped input, whatever PDFBox itself decides to do with it.
        byte[] truncated = "%PDF-1.4\n%garbage-not-a-real-pdf-structure".getBytes();
        assertThatNoException().isThrownBy(() -> DocumentMetadataParser.parse(DOC_URL, truncated));
    }

    @Test
    void findPaths_windowsUncPath_matched() {
        List<String> matches = DocumentMetadataParser.findPaths("Saved from \\\\fileserver\\shared\\docs\\handbook.docx");
        assertThat(matches).containsExactly("\\\\fileserver\\shared\\docs\\handbook.docx");
    }

    @Test
    void findPaths_unixHomePath_matched() {
        List<String> matches = DocumentMetadataParser.findPaths("/home/jdoe/Documents/handbook.odt");
        assertThat(matches).containsExactly("/home/jdoe/Documents/handbook.odt");
    }

    @Test
    void findPaths_plainAuthorName_noMatch() {
        assertThat(DocumentMetadataParser.findPaths("Jane Doe")).isEmpty();
    }

    private static byte[] buildPdf(String author, String creator, String producer) throws Exception {
        try (PDDocument doc = new PDDocument()) {
            doc.addPage(new org.apache.pdfbox.pdmodel.PDPage());
            PDDocumentInformation info = new PDDocumentInformation();
            if (author != null) info.setAuthor(author);
            if (creator != null) info.setCreator(creator);
            if (producer != null) info.setProducer(producer);
            doc.setDocumentInformation(info);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            doc.save(out);
            return out.toByteArray();
        }
    }
}
