package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Covers {@link SubdomainEnumModule#excludeCnamedHosts}, the fix for a confirmed false-positive
 * class in {@code SUBDOMAIN_NS_DELEGATION_TAKEOVER}: a hostname with a CNAME cannot also carry an
 * independent NS delegation (RFC 1035 S3.6.2), but {@link SubdomainDnsResolver}'s NS lookup goes
 * through dnsjava's {@code Lookup}, which transparently follows CNAME chains - so without this
 * filter, a CNAME'd hostname whose target happens to live in a zone hosted by a known cloud DNS
 * provider (e.g. Route53) gets that provider's nameservers misattributed to it, and
 * {@link NsTakeoverChecker} then "confirms" a takeover of a delegation that was never real.
 */
class SubdomainEnumModuleTest {

    @Test
    void cnamedHostname_excludedFromNsEligibleList() {
        List<String> discovered = List.of("clicks.example.com", "plain.example.com");
        Map<String, String> cnames = Map.of("clicks.example.com", "d111111111111.cloudfront.net");

        List<String> eligible = SubdomainEnumModule.excludeCnamedHosts(discovered, cnames);

        assertThat(eligible).containsExactly("plain.example.com");
    }

    @Test
    void noCnames_allHostnamesRemainEligible() {
        List<String> discovered = List.of("a.example.com", "b.example.com");

        List<String> eligible = SubdomainEnumModule.excludeCnamedHosts(discovered, Map.of());

        assertThat(eligible).containsExactlyInAnyOrder("a.example.com", "b.example.com");
    }

    @Test
    void everyHostnameCnamed_resultIsEmpty() {
        List<String> discovered = List.of("a.example.com", "b.example.com");
        Map<String, String> cnames = Map.of(
                "a.example.com", "target-a.example.net",
                "b.example.com", "target-b.example.net");

        List<String> eligible = SubdomainEnumModule.excludeCnamedHosts(discovered, cnames);

        assertThat(eligible).isEmpty();
    }

    @Test
    void emptyDiscoveredList_returnsEmpty() {
        assertThat(SubdomainEnumModule.excludeCnamedHosts(List.of(), Map.of())).isEmpty();
    }
}
