package org.freedonia.bloodhound.server.eol;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Parser-only tests against a canned endoflife.date response fixture (real shape, captured from the live API - https://endoflife.date/api/v1/products/nginx - while scoping this feature) - zero network calls. */
class EndOfLifeClientTest {

    private final EndOfLifeClient client = new EndOfLifeClient();

    private static final String NGINX_FIXTURE =
            """
            {
              "schema_version": "1.2.1",
              "result": {
                "name": "nginx",
                "releases": [
                  {
                    "name": "1.31",
                    "releaseDate": "2026-05-13",
                    "isEol": false,
                    "eolFrom": null,
                    "isMaintained": true,
                    "latest": {"name": "1.31.6", "date": "2026-09-15"}
                  },
                  {
                    "name": "1.29",
                    "releaseDate": "2025-06-24",
                    "isEol": true,
                    "eolFrom": "2026-05-13",
                    "isMaintained": false,
                    "latest": {"name": "1.29.8", "date": "2026-04-07"}
                  }
                ]
              }
            }
            """;

    @Test
    void parsesReleaseCyclesFromRealShape() {
        List<EolRelease> releases = client.parse(NGINX_FIXTURE);
        assertThat(releases).hasSize(2);
    }

    @Test
    void notYetEolRelease_isEolFalse_eolFromNull() {
        List<EolRelease> releases = client.parse(NGINX_FIXTURE);
        EolRelease current = releases.stream().filter(r -> r.releaseCycle().equals("1.31")).findFirst().orElseThrow();
        assertThat(current.isEol()).isFalse();
        assertThat(current.eolFrom()).isNull();
        assertThat(current.isMaintained()).isTrue();
        assertThat(current.latestVersionInCycle()).isEqualTo("1.31.6");
    }

    @Test
    void eolRelease_isEolTrue_eolFromParsed() {
        List<EolRelease> releases = client.parse(NGINX_FIXTURE);
        EolRelease old = releases.stream().filter(r -> r.releaseCycle().equals("1.29")).findFirst().orElseThrow();
        assertThat(old.isEol()).isTrue();
        assertThat(old.eolFrom()).isEqualTo(LocalDate.parse("2026-05-13"));
        assertThat(old.isMaintained()).isFalse();
    }

    @Test
    void nullResponse_returnsEmptyList() {
        assertThat(client.parse(null)).isEmpty();
    }

    @Test
    void malformedJson_returnsEmptyListRatherThanThrowing() {
        assertThat(client.parse("not json at all")).isEmpty();
    }

    @Test
    void missingReleasesArray_returnsEmptyList() {
        assertThat(client.parse("{\"result\": {\"name\": \"nginx\"}}")).isEmpty();
    }

    @Test
    void releaseWithNoLatestObject_stillParsed_latestVersionNull() {
        String json = """
                {"result": {"releases": [
                  {"name": "1.0", "isEol": true, "eolFrom": "2020-01-01", "isMaintained": false}
                ]}}
                """;
        List<EolRelease> releases = client.parse(json);
        assertThat(releases).hasSize(1);
        assertThat(releases.get(0).latestVersionInCycle()).isNull();
    }
}
