package org.freedonia.bloodhound.worker.modules.whois;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class RdapResponseParserTest {

    private static final String BOOTSTRAP_JSON =
            """
            {
              "version": "1.0",
              "publication": "2024-01-01T00:00:00Z",
              "services": [
                [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
                [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]]
              ]
            }
            """;

    private static final String DOMAIN_JSON =
            """
            {
              "objectClassName": "domain",
              "ldhName": "EXAMPLE.COM",
              "events": [
                {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"}
              ],
              "entities": [
                {"objectClassName": "entity", "roles": ["registrar"],
                 "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar, Inc."]]]}
              ],
              "nameservers": [
                {"objectClassName": "nameserver", "ldhName": "NS1.EXAMPLE.COM"},
                {"objectClassName": "nameserver", "ldhName": "NS2.EXAMPLE.COM"}
              ]
            }
            """;

    @Test
    void findRdapBaseUrl_matchesTldInGroupedServiceEntry() {
        assertThat(RdapResponseParser.findRdapBaseUrl(BOOTSTRAP_JSON, "com")).isEqualTo("https://rdap.verisign.com/com/v1/");
        assertThat(RdapResponseParser.findRdapBaseUrl(BOOTSTRAP_JSON, "net")).isEqualTo("https://rdap.verisign.com/com/v1/");
        assertThat(RdapResponseParser.findRdapBaseUrl(BOOTSTRAP_JSON, "org"))
                .isEqualTo("https://rdap.publicinterestregistry.org/rdap/");
    }

    @Test
    void findRdapBaseUrl_unknownTld_returnsNull() {
        assertThat(RdapResponseParser.findRdapBaseUrl(BOOTSTRAP_JSON, "doesnotexist")).isNull();
    }

    @Test
    void findRdapBaseUrl_caseInsensitive() {
        assertThat(RdapResponseParser.findRdapBaseUrl(BOOTSTRAP_JSON, "COM")).isEqualTo("https://rdap.verisign.com/com/v1/");
    }

    @Test
    void parseDomainResponse_extractsRegistrarDatesAndNameServers() {
        WhoisFields fields = RdapResponseParser.parseDomainResponse(DOMAIN_JSON);
        assertThat(fields.registrar()).isEqualTo("Example Registrar, Inc.");
        assertThat(fields.createdDate()).isEqualTo(Instant.parse("1995-08-14T04:00:00Z"));
        assertThat(fields.expiryDate()).isEqualTo(Instant.parse("2026-08-13T04:00:00Z"));
        assertThat(fields.nameServers()).containsExactlyInAnyOrder("ns1.example.com", "ns2.example.com");
        assertThat(fields.viaFallback()).isFalse();
    }

    @Test
    void parseDomainResponse_malformedJson_returnsEmptyFields() {
        WhoisFields fields = RdapResponseParser.parseDomainResponse("not json");
        assertThat(fields.registrar()).isNull();
        assertThat(fields.expiryDate()).isNull();
    }

    @Test
    void parseDomainResponse_noStatusField_emptyStatusCodes() {
        assertThat(RdapResponseParser.parseDomainResponse(DOMAIN_JSON).statusCodes()).isEmpty();
    }

    @Test
    void parseDomainResponse_extractsTopLevelStatusArray() {
        String json =
                """
                {
                  "objectClassName": "domain",
                  "status": ["client transfer prohibited", "active"]
                }
                """;
        assertThat(RdapResponseParser.parseDomainResponse(json).statusCodes())
                .containsExactly("client transfer prohibited", "active");
    }
}
