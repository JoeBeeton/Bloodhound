package org.freedonia.bloodhound.server.subdomain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.junit.jupiter.api.Test;

class SubdomainIngestionServiceTest {

    private final SubdomainRepository repository = mock(SubdomainRepository.class);
    private final SubdomainIngestionService service = new SubdomainIngestionService(repository);
    private final UUID targetId = UUID.randomUUID();

    @Test
    void newHostnameSynthesizesNewSubdomainFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of());

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "new.example.com",
                        "ipAddresses", List.of("1.2.3.4"),
                        "source", "CRTSH"))),
                List.of());

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("SUBDOMAIN_NEW_UNEXPECTED");
        verify(repository).upsert(eq(targetId), eq("new.example.com"), eq("CRTSH"), any(), isNull(), eq(true));
    }

    @Test
    void alreadyKnownHostnameStillResolving_synthesizesNoNewFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("known.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "known.example.com",
                        "ipAddresses", List.of("5.6.7.8"),
                        "source", "SUBFINDER"))),
                List.of());

        assertThat(findings).isEmpty();
        verify(repository).upsert(eq(targetId), eq("known.example.com"), eq("SUBFINDER"), any(), isNull(), eq(true));
    }

    @Test
    void alreadyKnownHostnameNoLongerResolving_synthesizesStaleFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("known.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "known.example.com",
                        "ipAddresses", List.of(),
                        "source", "SUBFINDER"))),
                List.of());

        assertThat(findings).hasSize(1);
        FindingPayload finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("SUBDOMAIN_STALE_NOT_RESOLVING");
        assertThat(finding.severity()).isEqualTo("LOW");
        assertThat(finding.affectedAsset()).isEqualTo("known.example.com");
    }

    /**
     * A first-time discovery with no address is neither stale (never known live) nor "new
     * surface" (nothing is listening) - it's inventoried, silently. 78,000 of this rule's
     * 102,000 historical findings were this case.
     */
    @Test
    void newHostnameNotResolving_isInventoriedButNotAFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of());

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "brandnew.example.com",
                        "ipAddresses", List.of(),
                        "source", "CRTSH"))),
                List.of());

        assertThat(findings).isEmpty();
        verify(repository).upsert(eq(targetId), eq("brandnew.example.com"), eq("CRTSH"), any(), isNull(), eq(true));
    }

    /** A long-tracked CT artifact that comes to life IS new surface, even though it's been in the table for months. */
    @Test
    void knownDormantHostnameResolvingForTheFirstTime_isNew() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("dormant.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of());

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "dormant.example.com",
                        "ipAddresses", List.of("203.0.113.9"),
                        "source", "CRTSH"))),
                List.of());

        assertThat(findings).extracting(FindingPayload::ruleId).containsExactly("SUBDOMAIN_NEW_UNEXPECTED");
    }

    @Test
    void confirmedDanglingCnameSynthesizesFindingAndPersistsTarget() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("stale.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("stale.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "stale.example.com",
                        "ipAddresses", List.of(),
                        "source", "CRTSH",
                        "cnameTarget", "old-bucket.s3.amazonaws.com",
                        "danglingConfirmed", true,
                        "danglingService", "AWS S3"))),
                List.of());

        // Also known already + no resolved IP -> SUBDOMAIN_STALE_NOT_RESOLVING fires
        // alongside the dangling-CNAME finding; both are independently true here.
        assertThat(findings).hasSize(2);
        assertThat(findings).extracting(FindingPayload::ruleId)
                .containsExactlyInAnyOrder("SUBDOMAIN_STALE_NOT_RESOLVING", "SUBDOMAIN_DANGLING_CNAME");
        FindingPayload finding = findings.stream()
                .filter(f -> f.ruleId().equals("SUBDOMAIN_DANGLING_CNAME"))
                .findFirst()
                .orElseThrow();
        assertThat(finding.severity()).isEqualTo("CRITICAL");
        assertThat(finding.affectedAsset()).isEqualTo("stale.example.com");
        assertThat(finding.evidence()).containsEntry("cnameTarget", "old-bucket.s3.amazonaws.com");

        verify(repository).upsert(eq(targetId), eq("stale.example.com"), eq("CRTSH"), any(), eq("old-bucket.s3.amazonaws.com"), eq(true));
    }

    @Test
    void publiclyListableBucketSynthesizesExposureFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("assets.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("assets.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "assets.example.com",
                        "ipAddresses", List.of("1.2.3.4"),
                        "source", "CRTSH",
                        "bucketProvider", "AWS_S3",
                        "bucketCheckUrl", "https://example-assets.s3.amazonaws.com/",
                        "bucketPubliclyListable", true))),
                List.of());

        assertThat(findings).hasSize(1);
        FindingPayload finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING");
        assertThat(finding.severity()).isEqualTo("CRITICAL");
        assertThat(finding.category()).isEqualTo("EXPOSURE");
        assertThat(finding.affectedAsset()).isEqualTo("assets.example.com");
        assertThat(finding.evidence()).containsEntry("provider", "AWS_S3");
        assertThat(finding.evidence()).containsEntry("checkUrl", "https://example-assets.s3.amazonaws.com/");
    }

    @Test
    void bucketMatchedButNotPubliclyListable_noExposureFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("assets.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("assets.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "assets.example.com",
                        "ipAddresses", List.of("1.2.3.4"),
                        "source", "CRTSH",
                        "bucketProvider", "AWS_S3",
                        "bucketCheckUrl", "https://example-assets.s3.amazonaws.com/",
                        "bucketPubliclyListable", false))),
                List.of());

        assertThat(findings).isEmpty();
    }

    @Test
    void confirmedNsTakeoverSynthesizesFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("legacy.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("legacy.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "legacy.example.com",
                        "ipAddresses", List.of("1.2.3.4"),
                        "source", "CRTSH",
                        "nsTakeoverConfirmed", true,
                        "nsTakeoverProvider", "AWS_ROUTE53",
                        "nsTakeoverNameserver", "ns-123.awsdns-45.com"))),
                List.of());

        assertThat(findings).hasSize(1);
        FindingPayload finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("SUBDOMAIN_NS_DELEGATION_TAKEOVER");
        assertThat(finding.severity()).isEqualTo("CRITICAL");
        assertThat(finding.category()).isEqualTo("SUBDOMAIN_HYGIENE");
        assertThat(finding.affectedAsset()).isEqualTo("legacy.example.com");
        assertThat(finding.evidence()).containsEntry("provider", "AWS_ROUTE53");
        assertThat(finding.evidence()).containsEntry("nameserver", "ns-123.awsdns-45.com");
    }

    @Test
    void nsMatchedButNotConfirmedTakeover_noFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("legacy.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("legacy.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "legacy.example.com",
                        "ipAddresses", List.of("1.2.3.4"),
                        "source", "CRTSH"))),
                List.of());

        assertThat(findings).isEmpty();
    }

    @Test
    void cnameMatchedButNotConfirmedDangling_noFindingAndTargetColumnStaysNull() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("claimed.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("claimed.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "claimed.example.com",
                        "ipAddresses", List.of(),
                        "source", "CRTSH",
                        "cnameTarget", "myapp.herokuapp.com",
                        "danglingConfirmed", false))),
                List.of());

        // No SUBDOMAIN_DANGLING_CNAME (danglingConfirmed=false), but this is an
        // already-known hostname with no resolved IP this run, so
        // SUBDOMAIN_STALE_NOT_RESOLVING correctly fires alongside its absence.
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("SUBDOMAIN_STALE_NOT_RESOLVING");
        verify(repository).upsert(eq(targetId), eq("claimed.example.com"), eq("CRTSH"), any(), isNull(), eq(true));
    }

    /**
     * The 41,000-finding case: a hostname that is in the table only because a CT log once
     * mentioned it, and has never resolved, is not "no longer resolving" - it never was.
     */
    @Test
    void knownButNeverResolvedHostname_isNotStale() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("ct-artifact.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of());

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "ct-artifact.example.com", "ipAddresses", List.of(), "source", "CRTSH"))),
                List.of());

        assertThat(findings).isEmpty();
        verify(repository).upsert(eq(targetId), eq("ct-artifact.example.com"), eq("CRTSH"), any(), isNull(), eq(true));
    }

    /** Every previously-resolving host dark in one run is the resolver, not the estate: no findings, liveness untouched. */
    @Test
    void everyPreviouslyResolvingHostDarkAtOnce_isTreatedAsResolverOutage() {
        Set<String> hosts = new java.util.HashSet<>();
        List<Map<String, Object>> entries = new java.util.ArrayList<>();
        for (int i = 0; i < SubdomainIngestionService.RESOLVER_OUTAGE_MIN_HOSTS; i++) {
            String h = "h" + i + ".example.com";
            hosts.add(h);
            entries.add(Map.of("hostname", h, "ipAddresses", List.of(), "source", "SUBFINDER"));
        }
        when(repository.findHostnames(targetId)).thenReturn(hosts);
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(hosts);

        List<FindingPayload> findings =
                service.ingestAndSynthesizeFindings(targetId, Map.of("subdomains", entries), List.of());

        assertThat(findings).isEmpty();
        verify(repository).upsert(eq(targetId), eq("h0.example.com"), eq("SUBFINDER"), any(), isNull(), eq(false));
    }

    /** One host resolving is enough to prove DNS works - the rest going dark is then a real (if large) decommission. */
    @Test
    void oneHostStillResolving_meansTheRestAreGenuinelyStale() {
        Set<String> hosts = new java.util.HashSet<>();
        List<Map<String, Object>> entries = new java.util.ArrayList<>();
        for (int i = 0; i < SubdomainIngestionService.RESOLVER_OUTAGE_MIN_HOSTS; i++) {
            String h = "h" + i + ".example.com";
            hosts.add(h);
            entries.add(Map.of("hostname", h, "ipAddresses", i == 0 ? List.of("203.0.113.5") : List.of(), "source", "SUBFINDER"));
        }
        when(repository.findHostnames(targetId)).thenReturn(hosts);
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(hosts);

        List<FindingPayload> findings =
                service.ingestAndSynthesizeFindings(targetId, Map.of("subdomains", entries), List.of());

        assertThat(findings).hasSize(SubdomainIngestionService.RESOLVER_OUTAGE_MIN_HOSTS - 1);
        assertThat(findings).allMatch(f -> f.ruleId().equals("SUBDOMAIN_STALE_NOT_RESOLVING"));
    }

    /** Below the floor there isn't enough signal to call an outage - a tiny estate going dark is reported as seen. */
    @Test
    void fewHostsAllDark_isBelowTheOutageFloorAndReportedNormally() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("a.example.com", "b.example.com"));
        when(repository.findHostnamesEverResolved(targetId)).thenReturn(Set.of("a.example.com", "b.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(
                        Map.of("hostname", "a.example.com", "ipAddresses", List.of(), "source", "SUBFINDER"),
                        Map.of("hostname", "b.example.com", "ipAddresses", List.of(), "source", "SUBFINDER"))),
                List.of());

        assertThat(findings).hasSize(2);
    }
}
