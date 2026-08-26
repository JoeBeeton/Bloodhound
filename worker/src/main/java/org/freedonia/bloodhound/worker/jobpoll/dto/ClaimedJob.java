package org.freedonia.bloodhound.worker.jobpoll.dto;

import java.util.Map;
import java.util.UUID;

/** Mirrors central-server's ClaimedJobDto - the two are independent copies of one wire contract, not a shared type. */
public record ClaimedJob(
        UUID id, UUID targetId, String hostname, UUID scanRunId, String moduleType, Map<String, Object> payload) {}
