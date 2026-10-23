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
    void absoluteLink_sameSiteSubdomain_keptAsIs() {
        String html = "<a href=\"https://cdn.example.com/report.docx\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html))
                .containsExactly("https://cdn.example.com/report.docx");
    }

    @Test
    void absoluteLink_genuinelyThirdPartyDomain_rejected() {
        // A security review found this had no host restriction at all: any http(s) link with a
        // document extension, anywhere on the internet, was downloaded and parsed by PDFBox/POI
        // on the shared worker. This is the actual regression case.
        String html = "<a href=\"https://attacker.example/malware.pdf\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html)).isEmpty();
    }

    @Test
    void absoluteLink_lookalikeDomainWithBaseHostAsPrefix_rejected() {
        // "example.com.evil.com" must never be confused for a legitimate subdomain of
        // "example.com" - the dot-anchored suffix check (not a bare endsWith/startsWith) is what
        // prevents that specific confusion.
        String html = "<a href=\"https://example.com.evil.com/malware.pdf\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html)).isEmpty();
    }

    @Test
    void absoluteLink_barePublicSuffixOfBaseHost_rejected() {
        // A rules-parity review found the old unbounded reverse-suffix check let a page at
        // "www.example.com" treat ANY dot-suffix of its own host as the same site, including a
        // bare TLD: "www.example.com".endsWith(".com") is true, so href="https://com/malware.pdf"
        // would have been downloaded and parsed as if it were the target's own document.
        String html = "<a href=\"https://com/malware.pdf\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls("https://www.example.com/", html)).isEmpty();
    }

    @Test
    void absoluteLink_grandparentDomainOfADeepSubdomainTarget_rejected() {
        // Same bug, a less extreme shape: the reverse direction is bounded to peeling exactly one
        // label, so a two-level-deep page can't reach all the way up to its grandparent domain.
        String html = "<a href=\"https://example.com/handbook.pdf\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls("https://a.blog.example.com/", html)).isEmpty();
    }

    @Test
    void absoluteLink_parentDomainOfASubdomainTarget_kept() {
        // The reverse subdomain relationship also counts as the same site - a page on
        // "blog.example.com" linking back to its own apex "example.com" is the same legitimate
        // pattern in the other direction.
        String html = "<a href=\"https://example.com/handbook.pdf\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls("https://blog.example.com/", html))
                .containsExactly("https://example.com/handbook.pdf");
    }

    @Test
    void absoluteLink_deeplyNestedSubdomainOfBaseHost_stillKept() {
        // The forward direction (linkHost a subdomain of baseHost, however deep) is deliberately
        // left unbounded - it was never the bug, since a more-specific name under the real site
        // carries no equivalent risk. Only the reverse direction is bounded to one label.
        String html = "<a href=\"https://assets.cdn.example.com/report.docx\">Report</a>";
        assertThat(DocumentLinkDecisionLogic.extractDocumentUrls(HOMEPAGE, html))
                .containsExactly("https://assets.cdn.example.com/report.docx");
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
