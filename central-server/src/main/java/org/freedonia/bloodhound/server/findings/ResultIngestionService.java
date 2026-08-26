package org.freedonia.bloodhound.server.findings;

import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

/** Thin transactional shell around the pure {@link FindingReconciler}: fetch open findings, plan, then write the plan. */
@Service
public class ResultIngestionService {

    private final FindingRepository findingRepository;

    public ResultIngestionService(FindingRepository findingRepository) {
        this.findingRepository = findingRepository;
    }

    public void ingest(UUID scanRunId, UUID targetId, String moduleType, List<FindingPayload> reported) {
        List<OpenFindingKey> currentlyOpen = findingRepository.findOpenKeys(targetId, moduleType);
        ReconciliationPlan plan = FindingReconciler.reconcile(currentlyOpen, reported);

        plan.toInsert().forEach(payload -> findingRepository.insert(scanRunId, targetId, moduleType, payload));
        if (!plan.toTouch().isEmpty()) {
            findingRepository.touch(plan.toTouch(), scanRunId);
        }
        if (!plan.toResolve().isEmpty()) {
            findingRepository.resolve(plan.toResolve());
        }
    }
}
