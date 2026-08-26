package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class NsTakeoverDecisionLogicTest {

    @Test
    void route53Nameserver_matchesAcrossAllFourTlds() {
        assertThat(NsTakeoverDecisionLogic.matchProvider("ns-123.awsdns-45.com"))
                .contains(new NsTakeoverDecisionLogic.Match(NsTakeoverDecisionLogic.Provider.AWS_ROUTE53));
        assertThat(NsTakeoverDecisionLogic.matchProvider("ns-678.awsdns-90.net"))
                .contains(new NsTakeoverDecisionLogic.Match(NsTakeoverDecisionLogic.Provider.AWS_ROUTE53));
        assertThat(NsTakeoverDecisionLogic.matchProvider("ns-111.awsdns-22.org"))
                .contains(new NsTakeoverDecisionLogic.Match(NsTakeoverDecisionLogic.Provider.AWS_ROUTE53));
        assertThat(NsTakeoverDecisionLogic.matchProvider("ns-333.awsdns-44.co.uk"))
                .contains(new NsTakeoverDecisionLogic.Match(NsTakeoverDecisionLogic.Provider.AWS_ROUTE53));
    }

    @Test
    void azureDnsNameserver_matches() {
        Optional<NsTakeoverDecisionLogic.Match> match = NsTakeoverDecisionLogic.matchProvider("ns1-01.azure-dns.com");
        assertThat(match).isPresent();
        assertThat(match.get().provider()).isEqualTo(NsTakeoverDecisionLogic.Provider.AZURE_DNS);
    }

    @Test
    void googleCloudDnsNameserver_matches() {
        Optional<NsTakeoverDecisionLogic.Match> match =
                NsTakeoverDecisionLogic.matchProvider("ns-cloud-a1.googledomains.com");
        assertThat(match).isPresent();
        assertThat(match.get().provider()).isEqualTo(NsTakeoverDecisionLogic.Provider.GOOGLE_CLOUD_DNS);
    }

    @Test
    void digitalOceanNameserver_matches() {
        Optional<NsTakeoverDecisionLogic.Match> match = NsTakeoverDecisionLogic.matchProvider("ns1.digitalocean.com");
        assertThat(match).isPresent();
        assertThat(match.get().provider()).isEqualTo(NsTakeoverDecisionLogic.Provider.DIGITALOCEAN);
    }

    @Test
    void selfHostedOrUnknownNameserver_noMatch() {
        // Not attacker-claimable via this mechanism even if genuinely lame - covered
        // separately (and only for the apex) by DNS_NS_LAME_DELEGATION.
        assertThat(NsTakeoverDecisionLogic.matchProvider("ns1.example-registrar.com")).isEmpty();
    }

    @Test
    void nullOrBlank_noMatch() {
        assertThat(NsTakeoverDecisionLogic.matchProvider(null)).isEmpty();
        assertThat(NsTakeoverDecisionLogic.matchProvider("")).isEmpty();
    }
}
