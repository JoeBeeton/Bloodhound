package org.freedonia.bloodhound.server.jobqueue.dto;

import java.util.Map;
import java.util.UUID;

public record ClaimedJobDto(
        UUID id, UUID targetId, String hostname, UUID scanRunId, String moduleType, Map<String, Object> payload) {}
