package org.freedonia.bloodhound.server.jobqueue.dto;

import java.time.Instant;
import java.util.UUID;

/**
 * {@code targetHostname}/{@code moduleType}/{@code currentHost} are only populated when the
 * worker is busy on a job belonging to the caller's own organization - workers are shared
 * infrastructure across every tenant, so a worker busy with another org's scan must
 * still show as "busy" (not lie and say idle) without leaking *what* it's scanning.
 *
 * <p>{@code currentHost} is the specific host a Tier 2 (one-job-per-host) module is
 * scanning right now - e.g. a particular subdomain, distinct from {@code targetHostname}
 * (the target's root). Null for Tier 1 jobs, which still fan out across many hosts
 * inside one job rather than one host per job.
 */
public record WorkerStatusDto(
        String workerId,
        String status,
        Instant lastHeartbeatAt,
        UUID targetId,
        String targetHostname,
        String moduleType,
        String currentHost) {}
