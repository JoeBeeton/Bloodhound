package org.freedonia.bloodhound.server.findings;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.freedonia.bloodhound.server.scoring.RuleWeightRepository;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;

class ResultIngestionServiceTest {

    private final FindingRepository repository = mock(FindingRepository.class);
    private final RuleWeightRepository ruleWeightRepository = mock(RuleWeightRepository.class);
    private final TargetRepository targetRepository = mock(TargetRepository.class);
    private final ResultIngestionService service =
            new ResultIngestionService(repository, ruleWeightRepository, targetRepository);

    private final UUID scanRunId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();
    private final UUID organizationId = UUID.randomUUID();

    private static FindingPayload payload(String ruleId, String asset) {
        return new FindingPayload(ruleId, "HIGH", "DNS", "title", "description", asset, Map.of());
    }

    @BeforeEach
    void noRulesDisabledByDefault() {
        when(targetRepository.findById(targetId))
                .thenReturn(Optional.of(new Target(
                        targetId, organizationId, "example.com", "OWN", "UNAUTHORIZED", 3600, Instant.now(), true,
                        Instant.now(), null)));
        when(ruleWeightRepository.findDisabledRuleIds(organizationId)).thenReturn(Set.of());
    }

    @Test
    void insertHittingTheUniqueIndex_isSwallowedNotPropagated() {
        // The DB-level backstop (idx_findings_target_rule_asset_open) for the concurrent-ingest
        // race a same-batch dedup fix in FindingReconciler can't reach: two overlapping ingest()
        // calls for the same target/module can both plan an insert for the same key before
        // either commits. When that happens, the loser's insert must not blow up the whole
        // ingest - the winner already recorded exactly what this call wanted.
        when(repository.findOpenKeys(targetId, "DNS_POSTURE", null)).thenReturn(List.of());
        FindingPayload finding = payload("DNS_SPF_MISSING", "example.com");
        doThrow(new DuplicateKeyException("duplicate key"))
                .when(repository)
                .insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(null), eq(finding));

        assertThatCode(() -> service.ingest(scanRunId, targetId, "DNS_POSTURE", null, List.of(finding)))
                .doesNotThrowAnyException();
    }

    @Test
    void oneDuplicateInABatch_doesNotPreventTheOthersFromInserting() {
        when(repository.findOpenKeys(targetId, "DNS_POSTURE", null)).thenReturn(List.of());
        FindingPayload conflicting = payload("DNS_SPF_MISSING", "example.com");
        FindingPayload clean = payload("DNS_CAA_MISSING", "example.com");
        doThrow(new DuplicateKeyException("duplicate key"))
                .when(repository)
                .insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(null), eq(conflicting));

        service.ingest(scanRunId, targetId, "DNS_POSTURE", null, List.of(conflicting, clean));

        verify(repository).insert(scanRunId, targetId, "DNS_POSTURE", null, clean);
    }

    @Test
    void normalIngest_insertsTouchesAndResolvesAsPlanned() {
        UUID openId = UUID.randomUUID();
        UUID staleId = UUID.randomUUID();
        when(repository.findOpenKeys(targetId, "DNS_POSTURE", null))
                .thenReturn(List.of(
                        new OpenFindingKey(openId, "DNS_SPF_MISSING", "example.com"),
                        new OpenFindingKey(staleId, "DNS_CAA_MISSING", "example.com")));
        FindingPayload reproduced = payload("DNS_SPF_MISSING", "example.com");
        FindingPayload fresh = payload("DNS_DMARC_MISSING", "example.com");

        service.ingest(scanRunId, targetId, "DNS_POSTURE", null, List.of(reproduced, fresh));

        verify(repository).insert(scanRunId, targetId, "DNS_POSTURE", null, fresh);
        verify(repository, times(1)).touch(List.of(openId), scanRunId);
        verify(repository, times(1)).resolve(List.of(staleId));
        verify(repository, times(0)).insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(null), eq(reproduced));
    }

    @Test
    void disabledRule_neverInserted_evenThoughItWasReported() {
        // The actual point of this test: a product/AppSec review found rules_catalog.enabled was
        // completely inert - returned by the API, rendered on the admin page, but never checked
        // anywhere. This is the enforcement that makes it real.
        when(repository.findOpenKeys(targetId, "DNS_POSTURE", null)).thenReturn(List.of());
        when(ruleWeightRepository.findDisabledRuleIds(organizationId)).thenReturn(Set.of("DNS_SPF_MISSING"));
        FindingPayload disabled = payload("DNS_SPF_MISSING", "example.com");
        FindingPayload stillEnabled = payload("DNS_CAA_MISSING", "example.com");

        service.ingest(scanRunId, targetId, "DNS_POSTURE", null, List.of(disabled, stillEnabled));

        verify(repository, times(0)).insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(null), eq(disabled));
        verify(repository).insert(scanRunId, targetId, "DNS_POSTURE", null, stillEnabled);
    }

    @Test
    void ruleDisabledAfterItsFindingWasAlreadyOpen_getsResolvedOnNextScan() {
        // A rule that was open, then got disabled, is no longer in this run's reported batch at
        // all (filtered before FindingReconciler ever sees it) - the exact same "not reproduced
        // this run" path that resolves any other stale finding, with no separate cleanup needed.
        UUID openId = UUID.randomUUID();
        when(repository.findOpenKeys(targetId, "DNS_POSTURE", null))
                .thenReturn(List.of(new OpenFindingKey(openId, "DNS_SPF_MISSING", "example.com")));
        when(ruleWeightRepository.findDisabledRuleIds(organizationId)).thenReturn(Set.of("DNS_SPF_MISSING"));
        FindingPayload nowDisabled = payload("DNS_SPF_MISSING", "example.com");

        service.ingest(scanRunId, targetId, "DNS_POSTURE", null, List.of(nowDisabled));

        verify(repository).resolve(List.of(openId));
        verify(repository, times(0)).insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(null), eq(nowDisabled));
    }

    @Test
    void disabledRuleIdsAreLookedUpForTheTargetsOwnOrganization_notGlobally() {
        // The actual security-relevant assertion: a review found the first version of the
        // disabled-rule filter above queried a global rules_catalog.enabled flag with no org
        // scoping at all, so any org's admin disabling a rule affected every tenant's ingestion.
        // This confirms the fix resolves organizationId from the target being ingested for and
        // passes exactly that org id to the lookup - not some other org's, and not none at all.
        when(repository.findOpenKeys(targetId, "DNS_POSTURE", null)).thenReturn(List.of());

        service.ingest(scanRunId, targetId, "DNS_POSTURE", null, List.of(payload("DNS_SPF_MISSING", "example.com")));

        verify(targetRepository).findById(targetId);
        verify(ruleWeightRepository).findDisabledRuleIds(organizationId);
    }

    @Test
    void targetNotFound_noDisabledRulesApplied_ingestStillProceeds() {
        // Defensive fallback for a target that's somehow gone by the time ingestion runs (e.g.
        // deleted mid-scan) - rather than fail the whole ingest or guess at an org, no rule
        // filtering is applied and findings are reconciled as reported.
        when(targetRepository.findById(targetId)).thenReturn(Optional.empty());
        when(repository.findOpenKeys(targetId, "DNS_POSTURE", null)).thenReturn(List.of());
        FindingPayload finding = payload("DNS_SPF_MISSING", "example.com");

        service.ingest(scanRunId, targetId, "DNS_POSTURE", null, List.of(finding));

        verify(repository).insert(scanRunId, targetId, "DNS_POSTURE", null, finding);
        verify(ruleWeightRepository, org.mockito.Mockito.never()).findDisabledRuleIds(org.mockito.ArgumentMatchers.any());
    }

    /**
     * The Tier 2 flapping bug (V53): a per-host NUCLEI_SCAN job for host A used to be reconciled
     * against every open NUCLEI_SCAN finding on the target, so it resolved host B's findings just by
     * not mentioning them. A scoped ingest must only ever look at - and only ever resolve - open
     * findings in its own scope, and must stamp the scope onto what it inserts so the next run's
     * host-A job finds them again.
     */
    @Test
    void scopedIngest_onlyReconcilesAgainstItsOwnScope_andStampsScopeOnInserts() {
        OpenFindingKey hostAOpen = new OpenFindingKey(UUID.randomUUID(), "NUCLEI_x", "https://a.example.com");
        when(repository.findOpenKeys(targetId, "NUCLEI_SCAN", "a.example.com")).thenReturn(List.of(hostAOpen));
        FindingPayload fresh = payload("NUCLEI_y", "https://a.example.com/admin");

        service.ingest(scanRunId, targetId, "NUCLEI_SCAN", "a.example.com", List.of(fresh));

        verify(repository).findOpenKeys(targetId, "NUCLEI_SCAN", "a.example.com");
        verify(repository, times(0)).findOpenKeys(eq(targetId), eq("NUCLEI_SCAN"), eq(null));
        verify(repository).insert(scanRunId, targetId, "NUCLEI_SCAN", "a.example.com", fresh);
        // The host-A finding not reproduced this run IS resolved - that's still correct within scope.
        verify(repository).resolve(List.of(hostAOpen.id()));
    }
}
