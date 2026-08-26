package org.freedonia.bloodhound.worker.modules.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AsnDecisionLogicTest {

    @Test
    void reverseIpv4_reversesOctets() {
        assertThat(AsnDecisionLogic.reverseIpv4("8.8.8.8")).isEqualTo("8.8.8.8");
        assertThat(AsnDecisionLogic.reverseIpv4("192.0.2.1")).isEqualTo("1.2.0.192");
    }

    @Test
    void reverseIpv4_rejectsNonIpv4() {
        assertThat(AsnDecisionLogic.reverseIpv4("2001:db8::1")).isNull();
        assertThat(AsnDecisionLogic.reverseIpv4("not-an-ip")).isNull();
        assertThat(AsnDecisionLogic.reverseIpv4("256.1.1.1")).isNull();
        assertThat(AsnDecisionLogic.reverseIpv4(null)).isNull();
    }

    @Test
    void reverseIpv6_nibbleReversesFullExpandedAddress() {
        assertThat(AsnDecisionLogic.reverseIpv6("::1"))
                .isEqualTo("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0");
        assertThat(AsnDecisionLogic.reverseIpv6("2001:4860:4860::8888"))
                .isEqualTo("8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2");
        assertThat(AsnDecisionLogic.reverseIpv6("2001:db8::1"))
                .isEqualTo("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2");
    }

    @Test
    void reverseIpv6_rejectsNonIpv6() {
        assertThat(AsnDecisionLogic.reverseIpv6("8.8.8.8")).isNull();
        assertThat(AsnDecisionLogic.reverseIpv6("not-an-ip")).isNull();
        assertThat(AsnDecisionLogic.reverseIpv6(null)).isNull();
    }

    @Test
    void reverseIpv6_ipv4MappedLiteral_normalizedToIpv4_rejected() {
        // The JDK parses this as an Inet4Address, not a genuine IPv6 address -
        // must not be nibble-reversed as if it were one.
        assertThat(AsnDecisionLogic.reverseIpv6("::ffff:10.0.0.1")).isNull();
    }

    @Test
    void parseAsn_extractsNumberFromOriginLookupFormat() {
        // Real-shaped Cymru origin.asn.cymru.com response.
        assertThat(AsnDecisionLogic.parseAsn("15169 | 8.8.8.0/24 | US | arin | 2000-03-30")).isEqualTo("AS15169");
    }

    @Test
    void parseAsn_handlesBlankOrMalformed() {
        assertThat(AsnDecisionLogic.parseAsn("")).isNull();
        assertThat(AsnDecisionLogic.parseAsn(null)).isNull();
    }

    @Test
    void parseOrg_extractsLastFieldFromAsnLookupFormat() {
        // Real-shaped Cymru AS{n}.asn.cymru.com response.
        assertThat(AsnDecisionLogic.parseOrg("15169 | US | arin | 2000-03-30 | GOOGLE, US")).isEqualTo("GOOGLE, US");
        assertThat(AsnDecisionLogic.parseOrg("16509 | US | arin | 2000-06-02 | AMAZON-02, US")).isEqualTo("AMAZON-02, US");
    }

    @Test
    void parseOrg_handlesBlankOrMalformed() {
        assertThat(AsnDecisionLogic.parseOrg("")).isNull();
        assertThat(AsnDecisionLogic.parseOrg(null)).isNull();
    }
}
