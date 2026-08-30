package org.freedonia.bloodhound.server.jobqueue;

import java.util.Optional;
import java.util.UUID;
import org.freedonia.bloodhound.server.jobqueue.dto.ScanRunDetail;
import org.freedonia.bloodhound.server.target.Target;
import org.freedonia.bloodhound.server.target.TargetRepository;

/**
 * Composes the full ScanRunDetail (run + jobs + attempts, including logOutput) org-scoped via the
 * run's target - shared by RunController's REST endpoint and the read-only MCP tool service (see
 * mcp.McpReadTools), so the composition and org-scoping logic exists exactly once. Empty means
 * either the run doesn't exist or its target doesn't belong to the given organization - same
 * "404 not 403" convention as TargetRepository#findByIdAndOrganization.
 */
public final class ScanRunDetailComposer {

    private ScanRunDetailComposer() {}

    public static Optional<ScanRunDetail> compose(
            UUID runId,
            UUID organizationId,
            ScanRunRepository scanRunRepository,
            ScanJobRepository scanJobRepository,
            ScanJobAttemptRepository scanJobAttemptRepository,
            TargetRepository targetRepository) {
        Optional<ScanRun> runOpt = scanRunRepository.findById(runId);
        if (runOpt.isEmpty()) {
            return Optional.empty();
        }
        ScanRun run = runOpt.get();
        Optional<Target> targetOpt = targetRepository.findByIdAndOrganization(run.targetId(), organizationId);
        if (targetOpt.isEmpty()) {
            return Optional.empty();
        }
        Target target = targetOpt.get();

        var jobs = scanJobRepository.findByScanRunId(runId).stream()
                .map(j -> new ScanRunDetail.ScanJobStatus(
                        j.id(),
                        j.moduleType(),
                        j.status(),
                        j.attemptCount(),
                        j.maxAttempts(),
                        j.errorDetail(),
                        scanJobAttemptRepository.findByScanJobId(j.id()).stream()
                                .map(a -> new ScanRunDetail.Attempt(
                                        a.attemptNumber(),
                                        a.claimedBy(),
                                        a.startedAt(),
                                        a.endedAt(),
                                        a.outcome(),
                                        a.errorDetail(),
                                        a.logOutput()))
                                .toList(),
                        JobPayloadHost.extract(j.payloadJson())))
                .toList();

        return Optional.of(new ScanRunDetail(
                run.id(),
                target.id(),
                target.hostname(),
                run.triggeredBy(),
                run.startedAt(),
                run.completedAt(),
                run.status(),
                jobs));
    }
}
