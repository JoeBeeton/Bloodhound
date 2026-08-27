package org.freedonia.bloodhound.server.diff;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.junit.jupiter.api.Test;

class FindingDiffEngineTest {

    private static Finding finding(String ruleId, String asset, String severity) {
        UUID id = UUID.randomUUID();
        return new Finding(
                id,
                "bh-test-1",
                UUID.randomUUID(),
                UUID.randomUUID(),
                "DNS_POSTURE",
                ruleId,
                severity,
                "DNS",
                "title",
                "description",
                "{}",
                asset,
                id,
                "OPEN",
                null,
                Instant.now(),
                Instant.now());
    }

    @Test
    void emptyBeforeAndAfter_producesNothing() {
        FindingDiffResult result = FindingDiffEngine.diff(List.of(), List.of());
        assertThat(result.newFindings()).isEmpty();
        assertThat(result.resolvedFindings()).isEmpty();
        assertThat(result.unchangedFindings()).isEmpty();
        assertThat(result.changedSeverity()).isEmpty();
    }

    @Test
    void openTheWholeTime_isUnchanged() {
        Finding f = finding("DNS_SPF_MISSING", "example.com", "HIGH");
        FindingDiffResult result = FindingDiffEngine.diff(List.of(f), List.of(f));
        assertThat(result.unchangedFindings()).containsExactly(f);
        assertThat(result.newFindings()).isEmpty();
        assertThat(result.resolvedFindings()).isEmpty();
        assertThat(result.changedSeverity()).isEmpty();
    }

    @Test
    void resolvedBetweenTheTwoRuns_isResolvedFinding() {
        Finding f = finding("DNS_SPF_MISSING", "example.com", "HIGH");
        FindingDiffResult result = FindingDiffEngine.diff(List.of(f), List.of());
        assertThat(result.resolvedFindings()).containsExactly(f);
        assertThat(result.newFindings()).isEmpty();
        assertThat(result.unchangedFindings()).isEmpty();
    }

    @Test
    void firstAppearsInAfter_isNewFinding() {
        Finding f = finding("DNS_SPF_MISSING", "example.com", "HIGH");
        FindingDiffResult result = FindingDiffEngine.diff(List.of(), List.of(f));
        assertThat(result.newFindings()).containsExactly(f);
        assertThat(result.resolvedFindings()).isEmpty();
        assertThat(result.unchangedFindings()).isEmpty();
    }

    @Test
    void severityChangedBetweenTheTwoRuns_isChangedSeverity() {
        Finding before = finding("TLS_WEAK_CIPHER_SUITE", "example.com", "MEDIUM");
        Finding after = finding("TLS_WEAK_CIPHER_SUITE", "example.com", "HIGH");
        FindingDiffResult result = FindingDiffEngine.diff(List.of(before), List.of(after));
        assertThat(result.changedSeverity()).containsExactly(new FindingDiffResult.SeverityChange(before, after));
        assertThat(result.unchangedFindings()).isEmpty();
        assertThat(result.newFindings()).isEmpty();
        assertThat(result.resolvedFindings()).isEmpty();
    }

    /**
     * The trickiest case: a finding resolved and then reappeared as a fresh
     * row (per FindingReconciler's documented design, reappearance after
     * resolution always creates a new id) entirely between runA and runB.
     * Both the "before" instance and the "after" instance are open at their
     * respective points in time and share the same (ruleId, affectedAsset)
     * key despite being different rows with different ids - the net effect
     * from runA to runB should read as unchanged, not as one resolution plus
     * one new finding, since from the caller's perspective it was open at
     * both compared points.
     */
    @Test
    void resolvedThenReappearedEntirelyBetweenTheTwoRuns_readsAsUnchanged() {
        Finding beforeInstance = finding("DNS_SPF_MISSING", "example.com", "HIGH");
        Finding afterInstance = finding("DNS_SPF_MISSING", "example.com", "HIGH"); // fresh id, same rule+asset+severity

        assertThat(beforeInstance.id()).isNotEqualTo(afterInstance.id());

        FindingDiffResult result = FindingDiffEngine.diff(List.of(beforeInstance), List.of(afterInstance));

        assertThat(result.unchangedFindings()).containsExactly(afterInstance);
        assertThat(result.newFindings()).isEmpty();
        assertThat(result.resolvedFindings()).isEmpty();
        assertThat(result.changedSeverity()).isEmpty();
    }

    @Test
    void resolvedThenReappearedWithDifferentSeverity_readsAsChangedSeverityNotNewPlusResolved() {
        Finding beforeInstance = finding("DNS_SPF_MISSING", "example.com", "HIGH");
        Finding afterInstance = finding("DNS_SPF_MISSING", "example.com", "MEDIUM");

        FindingDiffResult result = FindingDiffEngine.diff(List.of(beforeInstance), List.of(afterInstance));

        assertThat(result.changedSeverity()).containsExactly(new FindingDiffResult.SeverityChange(beforeInstance, afterInstance));
        assertThat(result.newFindings()).isEmpty();
        assertThat(result.resolvedFindings()).isEmpty();
        assertThat(result.unchangedFindings()).isEmpty();
    }

    @Test
    void differentAffectedAssetsForSameRule_areIndependent() {
        Finding cookieA = finding("COOKIE_MISSING_SECURE_FLAG", "session_id", "MEDIUM");
        Finding cookieB = finding("COOKIE_MISSING_SECURE_FLAG", "csrf_token", "MEDIUM");

        // cookieA open the whole time; cookieB is new in "after".
        FindingDiffResult result = FindingDiffEngine.diff(List.of(cookieA), List.of(cookieA, cookieB));

        assertThat(result.unchangedFindings()).containsExactly(cookieA);
        assertThat(result.newFindings()).containsExactly(cookieB);
        assertThat(result.resolvedFindings()).isEmpty();
    }

    @Test
    void mixedRealisticScan_bucketsEachFindingCorrectly() {
        Finding stable = finding("DNS_CAA_MISSING", "example.com", "LOW");
        Finding resolved = finding("HEADER_CSP_MISSING", "example.com", "MEDIUM");
        Finding newOne = finding("TLS_NO_HSTS", "example.com", "MEDIUM");

        FindingDiffResult result = FindingDiffEngine.diff(List.of(stable, resolved), List.of(stable, newOne));

        assertThat(result.unchangedFindings()).containsExactly(stable);
        assertThat(result.resolvedFindings()).containsExactly(resolved);
        assertThat(result.newFindings()).containsExactly(newOne);
        assertThat(result.changedSeverity()).isEmpty();
    }
}
