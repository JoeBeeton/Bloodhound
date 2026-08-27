package org.freedonia.bloodhound.server.findings;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;

class ResultIngestionServiceTest {

    private final FindingRepository repository = mock(FindingRepository.class);
    private final ResultIngestionService service = new ResultIngestionService(repository);

    private final UUID scanRunId = UUID.randomUUID();
    private final UUID targetId = UUID.randomUUID();

    private static FindingPayload payload(String ruleId, String asset) {
        return new FindingPayload(ruleId, "HIGH", "DNS", "title", "description", asset, Map.of());
    }

    @Test
    void insertHittingTheUniqueIndex_isSwallowedNotPropagated() {
        // The DB-level backstop (idx_findings_target_rule_asset_open) for the concurrent-ingest
        // race a same-batch dedup fix in FindingReconciler can't reach: two overlapping ingest()
        // calls for the same target/module can both plan an insert for the same key before
        // either commits. When that happens, the loser's insert must not blow up the whole
        // ingest - the winner already recorded exactly what this call wanted.
        when(repository.findOpenKeys(targetId, "DNS_POSTURE")).thenReturn(List.of());
        FindingPayload finding = payload("DNS_SPF_MISSING", "example.com");
        doThrow(new DuplicateKeyException("duplicate key"))
                .when(repository)
                .insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(finding));

        assertThatCode(() -> service.ingest(scanRunId, targetId, "DNS_POSTURE", List.of(finding)))
                .doesNotThrowAnyException();
    }

    @Test
    void oneDuplicateInABatch_doesNotPreventTheOthersFromInserting() {
        when(repository.findOpenKeys(targetId, "DNS_POSTURE")).thenReturn(List.of());
        FindingPayload conflicting = payload("DNS_SPF_MISSING", "example.com");
        FindingPayload clean = payload("DNS_CAA_MISSING", "example.com");
        doThrow(new DuplicateKeyException("duplicate key"))
                .when(repository)
                .insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(conflicting));

        service.ingest(scanRunId, targetId, "DNS_POSTURE", List.of(conflicting, clean));

        verify(repository).insert(scanRunId, targetId, "DNS_POSTURE", clean);
    }

    @Test
    void normalIngest_insertsTouchesAndResolvesAsPlanned() {
        UUID openId = UUID.randomUUID();
        UUID staleId = UUID.randomUUID();
        when(repository.findOpenKeys(targetId, "DNS_POSTURE"))
                .thenReturn(List.of(
                        new OpenFindingKey(openId, "DNS_SPF_MISSING", "example.com"),
                        new OpenFindingKey(staleId, "DNS_CAA_MISSING", "example.com")));
        FindingPayload reproduced = payload("DNS_SPF_MISSING", "example.com");
        FindingPayload fresh = payload("DNS_DMARC_MISSING", "example.com");

        service.ingest(scanRunId, targetId, "DNS_POSTURE", List.of(reproduced, fresh));

        verify(repository).insert(scanRunId, targetId, "DNS_POSTURE", fresh);
        verify(repository, times(1)).touch(List.of(openId), scanRunId);
        verify(repository, times(1)).resolve(List.of(staleId));
        verify(repository, times(0)).insert(eq(scanRunId), eq(targetId), eq("DNS_POSTURE"), eq(reproduced));
    }
}
