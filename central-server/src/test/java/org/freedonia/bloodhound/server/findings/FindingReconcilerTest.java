package org.freedonia.bloodhound.server.findings;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class FindingReconcilerTest {

    private static FindingPayload payload(String ruleId, String asset) {
        return new FindingPayload(ruleId, "HIGH", "DNS", "title", "description", asset, Map.of());
    }

    @Test
    void emptyOpenAndEmptyReported_producesNothing() {
        ReconciliationPlan plan = FindingReconciler.reconcile(List.of(), List.of());
        assertThat(plan.toInsert()).isEmpty();
        assertThat(plan.toTouch()).isEmpty();
        assertThat(plan.toResolve()).isEmpty();
    }

    @Test
    void noExistingOpenFindings_allReportedAreNew() {
        List<FindingPayload> reported = List.of(payload("DNS_SPF_MISSING", "example.com"), payload("DNS_CAA_MISSING", "example.com"));
        ReconciliationPlan plan = FindingReconciler.reconcile(List.of(), reported);
        assertThat(plan.toInsert()).containsExactlyElementsOf(reported);
        assertThat(plan.toTouch()).isEmpty();
        assertThat(plan.toResolve()).isEmpty();
    }

    @Test
    void allExistingFindingsReproduced_noDuplicatesNoResolutions() {
        UUID existingId = UUID.randomUUID();
        List<OpenFindingKey> open = List.of(new OpenFindingKey(existingId, "DNS_SPF_MISSING", "example.com"));
        List<FindingPayload> reported = List.of(payload("DNS_SPF_MISSING", "example.com"));

        ReconciliationPlan plan = FindingReconciler.reconcile(open, reported);

        assertThat(plan.toInsert()).isEmpty();
        assertThat(plan.toTouch()).containsExactly(existingId);
        assertThat(plan.toResolve()).isEmpty();
    }

    @Test
    void previouslyOpenFindingNotReproduced_getsResolved() {
        UUID staleId = UUID.randomUUID();
        List<OpenFindingKey> open = List.of(
                new OpenFindingKey(staleId, "DNS_SPF_MISSING", "example.com"),
                new OpenFindingKey(UUID.randomUUID(), "DNS_CAA_MISSING", "example.com"));
        // Only the CAA finding reproduces this run; SPF is now fixed.
        List<FindingPayload> reported = List.of(payload("DNS_CAA_MISSING", "example.com"));

        ReconciliationPlan plan = FindingReconciler.reconcile(open, reported);

        assertThat(plan.toResolve()).containsExactly(staleId);
        assertThat(plan.toTouch()).hasSize(1);
        assertThat(plan.toInsert()).isEmpty();
    }

    @Test
    void findingNotCurrentlyOpen_reappearing_isTreatedAsFreshNotReopened() {
        // A RESOLVED finding is, by construction, absent from "currentlyOpen"
        // (the repository only fetches status='OPEN' rows) - so when it's
        // reported again, reconcile() has no way to know it existed before
        // and correctly plans a brand-new insert rather than a "reopen".
        List<FindingPayload> reported = List.of(payload("DNS_SPF_MISSING", "example.com"));
        ReconciliationPlan plan = FindingReconciler.reconcile(List.of(), reported);

        assertThat(plan.toInsert()).containsExactly(reported.get(0));
        assertThat(plan.toTouch()).isEmpty();
    }

    @Test
    void differentAffectedAssetsForSameRule_areIndependentFindings() {
        UUID cookieAId = UUID.randomUUID();
        List<OpenFindingKey> open = List.of(new OpenFindingKey(cookieAId, "COOKIE_MISSING_SECURE_FLAG", "session_id"));
        List<FindingPayload> reported = List.of(
                payload("COOKIE_MISSING_SECURE_FLAG", "session_id"), payload("COOKIE_MISSING_SECURE_FLAG", "csrf_token"));

        ReconciliationPlan plan = FindingReconciler.reconcile(open, reported);

        assertThat(plan.toTouch()).containsExactly(cookieAId);
        assertThat(plan.toInsert()).extracting(FindingPayload::affectedAsset).containsExactly("csrf_token");
        assertThat(plan.toResolve()).isEmpty();
    }
}
