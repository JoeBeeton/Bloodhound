package org.freedonia.bloodhound.worker.modules.whois;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;

class RawWhoisTextParserTest {

    private static final String DOMAIN_RESPONSE =
            """
            Domain Name: EXAMPLE.COM
            Registry Domain ID: 123456_DOMAIN_COM-VRSN
            Registrar WHOIS Server: whois.example-registrar.com
            Updated Date: 2024-08-14T04:00:00Z
            Creation Date: 1995-08-14T04:00:00Z
            Registry Expiry Date: 2026-08-13T04:00:00Z
            Registrar: Example Registrar, Inc.
            Name Server: NS1.EXAMPLE.COM
            Name Server: NS2.EXAMPLE.COM
            """;

    private static final String IANA_RESPONSE =
            """
            % IANA WHOIS server
            % for more information on IANA, visit http://www.iana.org

            refer:        whois.verisign-grs.com

            domain:       COM
            """;

    @Test
    void parse_extractsRegistrarDatesAndNameServers() {
        WhoisFields fields = RawWhoisTextParser.parse(DOMAIN_RESPONSE);
        assertThat(fields.registrar()).isEqualTo("Example Registrar, Inc.");
        assertThat(fields.createdDate()).isEqualTo(Instant.parse("1995-08-14T04:00:00Z"));
        assertThat(fields.expiryDate()).isEqualTo(Instant.parse("2026-08-13T04:00:00Z"));
        assertThat(fields.nameServers()).containsExactly("ns1.example.com", "ns2.example.com");
        assertThat(fields.viaFallback()).isTrue();
    }

    @Test
    void parse_alternateFieldLabels_paidTillAndRegisteredOn() {
        String text = "Registrar: Alt Registrar\nRegistered On: 2010-01-01\npaid-till: 2027-01-01\n";
        WhoisFields fields = RawWhoisTextParser.parse(text);
        assertThat(fields.registrar()).isEqualTo("Alt Registrar");
        assertThat(fields.createdDate()).isNotNull();
        assertThat(fields.expiryDate()).isNotNull();
    }

    @Test
    void parse_emptyText_returnsEmptyFields() {
        WhoisFields fields = RawWhoisTextParser.parse("");
        assertThat(fields.registrar()).isNull();
        assertThat(fields.viaFallback()).isTrue();
    }

    @Test
    void parseReferralServer_extractsReferLine() {
        assertThat(RawWhoisTextParser.parseReferralServer(IANA_RESPONSE)).isEqualTo("whois.verisign-grs.com");
    }

    @Test
    void parseReferralServer_noReferLine_returnsNull() {
        assertThat(RawWhoisTextParser.parseReferralServer("no refer here")).isNull();
    }

    @Test
    void parse_extractsMultipleDomainStatusLines() {
        String text = "Registrar: Some Registrar\n"
                + "Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited\n"
                + "Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited\n";
        assertThat(RawWhoisTextParser.parse(text).statusCodes())
                .containsExactly("clientTransferProhibited", "clientUpdateProhibited");
    }

    @Test
    void parse_noDomainStatusLines_emptyStatusCodes() {
        assertThat(RawWhoisTextParser.parse("Registrar: Some Registrar\n").statusCodes()).isEmpty();
    }
}
