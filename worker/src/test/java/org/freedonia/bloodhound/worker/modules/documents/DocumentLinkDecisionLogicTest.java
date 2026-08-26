package org.freedonia.bloodhound.worker.modules.documents;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class DocumentLinkDecisionLogicTest {

    private static final String HOMEPAGE = "https://example.com/";

    @Test
    void nullOrBlankHtml_noLinks() {
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, null)).isEmpty();
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, "")).isEmpty();
    }

    @Test
    void relativePdfLink_resolvedToAbsolute() {
        String html = "<html><body><a href=\"/files/handbook.pdf\">Handbook</a></body></html>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html))
                .containsExactly("https://example.com/files/handbook.pdf");
    }

    @Test
    void absoluteLink_keptAsIs() {
        String html = "<a href=\"https://cdn.example.com/report.docx\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html))
                .containsExactly("https://cdn.example.com/report.docx");
    }

    @Test
    void nonDocumentLinks_ignored() {
        String html = "<a href=\"/about\">About</a><a href=\"/logo.png\">Logo</a><a href=\"/app.js\">App</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html)).isEmpty();
    }

    @Test
    void allSupportedExtensions_matchedIndividually() {
        for (String ext : List.of("pdf", "docx", "doc", "xlsx", "xls", "pptx", "ppt")) {
            String html = "<a href=\"/file." + ext + "\">file</a>";
            assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html))
                    .as("extension ." + ext)
                    .containsExactly("https://example.com/file." + ext);
        }
    }

    @Test
    void queryStringAfterExtension_stillMatched() {
        String html = "<a href=\"/files/report.pdf?download=1\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html))
                .containsExactly("https://example.com/files/report.pdf?download=1");
    }

    @Test
    void mailtoAndJavascriptSchemes_ignored() {
        String html = "<a href=\"mailto:security@example.com\">mail</a>"
                + "<a href=\"javascript:void(0)\">js</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html)).isEmpty();
    }

    @Test
    void duplicateLinks_deduplicated() {
        String html = "<a href=\"/a.pdf\">1</a><a href=\"/a.pdf\">2</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html)).hasSize(1);
    }

    @Test
    void exceedsMaxDocumentsPerHost_capped() {
        StringBuilder html = new StringBuilder();
        for (int i = 0; i < 20; i++) {
            html.append("<a href=\"/doc").append(i).append(".pdf\">doc</a>");
        }
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html.toString()))
                .hasSize(DocumentLinkDecisionLogic.MAX_DOCUMENTS_PER_HOST);
    }
}
