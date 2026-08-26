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
        verify(repository).upsert(eq(targetId), eq("new.example.com"), eq("CRTSH"), any(), isNull());
    }

    @Test
    void alreadyKnownHostnameStillResolving_synthesizesNoNewFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "known.example.com",
                        "ipAddresses", List.of("5.6.7.8"),
                        "source", "SUBFINDER"))),
                List.of());

        assertThat(findings).isEmpty();
        verify(repository).upsert(eq(targetId), eq("known.example.com"), eq("SUBFINDER"), any(), isNull());
    }

    @Test
    void alreadyKnownHostnameNoLongerResolving_synthesizesStaleFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("known.example.com"));

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

    @Test
    void newHostnameNotResolving_notFlaggedStale() {
        // isNew=true takes precedence - a hostname discovered for the first time with no
        // current IP isn't "stale" (it was never known to be live), it's just a fresh
        // discovery with no live A/AAAA - not the SUBDOMAIN_STALE_NOT_RESOLVING scenario.
        when(repository.findHostnames(targetId)).thenReturn(Set.of());

        List<FindingPayload> findings = service.ingestAndSynthesizeFindings(
                targetId,
                Map.of("subdomains", List.of(Map.of(
                        "hostname", "brandnew.example.com",
                        "ipAddresses", List.of(),
                        "source", "CRTSH"))),
                List.of());

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).ruleId()).isEqualTo("SUBDOMAIN_NEW_UNEXPECTED");
    }

    @Test
    void confirmedDanglingCnameSynthesizesFindingAndPersistsTarget() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("stale.example.com"));

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

        verify(repository).upsert(
                eq(targetId), eq("stale.example.com"), eq("CRTSH"), any(), eq("old-bucket.s3.amazonaws.com"));
    }

    @Test
    void publiclyListableBucketSynthesizesExposureFinding() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("assets.example.com"));

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
    void cnameMatchedButNotConfirmedDangling_noFindingAndTargetColumnStaysNull() {
        when(repository.findHostnames(targetId)).thenReturn(Set.of("claimed.example.com"));

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
        verify(repository).upsert(eq(targetId), eq("claimed.example.com"), eq("CRTSH"), any(), isNull());
    }
}
