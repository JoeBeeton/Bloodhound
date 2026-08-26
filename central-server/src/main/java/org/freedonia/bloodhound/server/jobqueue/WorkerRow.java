package org.freedonia.bloodhound.server.jobqueue;

import java.time.Instant;
import java.util.UUID;

/**
 * One worker's presence + (if genuinely busy right now) what it's working on. The
 * job/target fields are only non-null when {@code current_job_id} points at a job
 * that's still actually CLAIMED/RUNNING - the join in {@link WorkerRepository} guards
 * against a stale reference (e.g. a missed clear) being reported as busy forever.
 *
 * <p>{@code targetOrganizationId} exists purely so {@link WorkersController} can decide
 * whether the caller is allowed to see {@code targetHostname}/{@code moduleType} - it's
 * never itself returned to the frontend.
 */
public record WorkerRow(
        String workerId,
        Instant lastHeartbeatAt,
        UUID currentJobId,
        String moduleType,
        UUID targetId,
        String targetHostname,
        UUID targetOrganizationId,
        String currentHost) {}
