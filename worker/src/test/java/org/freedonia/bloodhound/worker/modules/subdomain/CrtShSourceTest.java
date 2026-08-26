package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Pure JSON-parsing tests against canned crt.sh responses - zero network calls. */
class CrtShSourceTest {

    @Test
    void parsesMultipleNamesPerEntryStripsWildcardsAndDedupes() throws Exception {
        String json =
                """
                [
                  {"name_value": "www.example.com\\napi.example.com"},
                  {"name_value": "*.staging.example.com"},
                  {"name_value": "www.example.com"},
                  {"name_value": "api.example.com\\nexample.com"}
                ]
                """;

        List<String> result = CrtShSource.parse("example.com", json);

        assertThat(result).containsExactlyInAnyOrder("www.example.com", "api.example.com", "staging.example.com");
    }

    @Test
    void excludesUnrelatedAndNonSubdomainNames() throws Exception {
        String json =
                """
                [
                  {"name_value": "www.example.com"},
                  {"name_value": "notexample.com"},
                  {"name_value": "www.other.com"},
                  {"name_value": "evilexample.com"}
                ]
                """;

        List<String> result = CrtShSource.parse("example.com", json);

        assertThat(result).containsExactly("www.example.com");
    }

    @Test
    void handlesEmptyArray() throws Exception {
        assertThat(CrtShSource.parse("example.com", "[]")).isEmpty();
    }

    @Test
    void handlesEntryWithNullNameValue() throws Exception {
        String json = "[{\"name_value\": null}, {\"name_value\": \"a.example.com\"}]";

        assertThat(CrtShSource.parse("example.com", json)).containsExactly("a.example.com");
    }

    @Test
    void throwsOnEmptyResponse() {
        assertThatThrownBy(() -> CrtShSource.parse("example.com", "")).isInstanceOf(java.io.IOException.class);
    }

    @Test
    void throwsOnMalformedJson() {
        assertThatThrownBy(() -> CrtShSource.parse("example.com", "{not json")).isInstanceOf(java.io.IOException.class);
    }

    @Test
    void throwsOnUnexpectedShape() {
        assertThatThrownBy(() -> CrtShSource.parse("example.com", "{\"error\": \"rate limited\"}"))
                .isInstanceOf(java.io.IOException.class);
    }
}
