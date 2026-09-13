package org.freedonia.bloodhound.server.compound;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.server.findings.Finding;
import org.freedonia.bloodhound.server.findings.FindingPayload;
import org.freedonia.bloodhound.server.findings.FindingRepository;
import org.freedonia.bloodhound.server.findings.ResultIngestionService;
import org.springframework.stereotype.Service;

/**
 * Thin transactional shell around the pure {@link CompoundRiskEngine}, same
 * fetch/pure-logic/persist shape as {@link org.freedonia.bloodhound.server.findings.ResultIngestionService}
 * itself. Runs once per completed scan_run (see ScanRunService#checkAndCompleteRun),
 * <i>before</i> scoring, so a snapshot's finding_counts reflect that run's
 * compound findings too.
 *
 * <p>Deliberately reuses {@link ResultIngestionService#ingest} with a
 * synthetic module_type of {@code COMPOUND_ANALYSIS} rather than writing
 * bespoke insert/update logic - this gets correct dedup AND automatic
 * resolution for free: if a later scan's open-findings set no longer
 * reproduces a pattern (e.g. the .env file got removed), this run's
 * compound-analysis pass simply won't re-report that compound finding, and
 * the existing reconciliation logic in ResultIngestionService/FindingReconciler
 * closes it exactly like it already does for every real scan module's
 * findings.
 */
@Service
public class CompoundRiskAnalysisService {

    private final FindingRepository findingRepository;
    private final ResultIngestionService resultIngestionService;

    public CompoundRiskAnalysisService(
            FindingRepository findingRepository, ResultIngestionService resultIngestionService) {
        this.findingRepository = findingRepository;
        this.resultIngestionService = resultIngestionService;
    }

    public void analyzeAndIngest(UUID targetId, UUID scanRunId) {
        List<Finding> openFindings = findingRepository.findOpenForScoring(targetId);
        List<CompoundMatch> matches = CompoundRiskEngine.evaluate(openFindings);
        List<FindingPayload> payloads = matches.stream().map(this::toPayload).toList();
        resultIngestionService.ingest(scanRunId, targetId, "COMPOUND_ANALYSIS", null, payloads);
    }

    private FindingPayload toPayload(CompoundMatch match) {
        List<Map<String, Object>> contributing = match.contributingFindings().stream()
                .map(f -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("findingId", f.id().toString());
                    m.put("ruleId", f.ruleId());
                    m.put("severity", f.severity());
                    m.put("affectedAsset", f.affectedAsset());
                    return (Map<String, Object>) m;
                })
                .toList();
        return new FindingPayload(
                match.pattern().ruleId(),
                match.pattern().severity(),
                "COMPOUND",
                match.pattern().titleTemplate(),
                match.pattern().descriptionTemplate(),
                match.affectedAsset(),
                Map.of("contributingFindings", contributing));
    }
}
