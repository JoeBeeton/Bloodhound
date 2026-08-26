package org.freedonia.bloodhound.worker.modules.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class WordPressRestApiDecisionLogicTest {

    private static List<String> names(List<Technology> found) {
        return found.stream().map(Technology::name).toList();
    }

    @Test
    void realWorldResponse_extractsInstalledPlugins() {
        // Real /wp-json/ root response captured live against www.example.co.uk - a site that
        // strips every other WordPress fingerprint (no generator tag, no wp-content/wp-includes
        // references anywhere in the page) yet still openly lists its plugins here.
        String body = """
                {"name":"Example","description":"","url":"http:\\/\\/example.co.uk\\/wp","home":"https:\\/\\/example.co.uk",
                "namespaces":["oembed\\/1.0","yoast\\/v1","redirection\\/v1","wordfence\\/v1",
                "regenerate-thumbnails\\/v1","wp\\/v2","wp-site-health\\/v1","wp-block-editor\\/v1"],
                "authentication":[]}
                """;
        List<Technology> found = WordPressRestApiDecisionLogic.decide(body);
        assertThat(names(found)).containsExactlyInAnyOrder(
                "WordPress Plugin: Yoast SEO",
                "WordPress Plugin: Redirection",
                "WordPress Plugin: Wordfence Security",
                "WordPress Plugin: Regenerate Thumbnails");
        assertThat(found).allMatch(t -> t.category().equals(Technology.CMS) && t.version() == null);
    }

    @Test
    void coreNamespacesOnly_producesNoPlugins() {
        String body = """
                {"namespaces":["oembed/1.0","wp/v2","wp-site-health/v1","wp-block-editor/v1"]}
                """;
        assertThat(WordPressRestApiDecisionLogic.decide(body)).isEmpty();
    }

    @Test
    void unrecognizedNamespace_isSkippedRatherThanGuessed() {
        String body = """
                {"namespaces":["some-plugin-nobody-has-mapped/v1"]}
                """;
        assertThat(WordPressRestApiDecisionLogic.decide(body)).isEmpty();
    }

    @Test
    void wooCommerceNamespaceVersions_allMapToSameTechnology() {
        String body = """
                {"namespaces":["wc/v1","wc/v2","wc/v3"]}
                """;
        List<Technology> found = WordPressRestApiDecisionLogic.decide(body);
        assertThat(names(found)).containsExactly("WordPress Plugin: WooCommerce");
    }

    @Test
    void nullOrBlankBody_returnsEmptyRatherThanThrowing() {
        assertThat(WordPressRestApiDecisionLogic.decide(null)).isEmpty();
        assertThat(WordPressRestApiDecisionLogic.decide("")).isEmpty();
        assertThat(WordPressRestApiDecisionLogic.decide("   ")).isEmpty();
    }

    @Test
    void malformedJson_returnsEmptyRatherThanThrowing() {
        assertThat(WordPressRestApiDecisionLogic.decide("not json at all")).isEmpty();
    }

    @Test
    void missingNamespacesField_returnsEmpty() {
        assertThat(WordPressRestApiDecisionLogic.decide("{\"name\":\"Some Site\"}")).isEmpty();
    }
}
