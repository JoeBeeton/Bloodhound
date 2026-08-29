package org.freedonia.bloodhound.server.jobqueue.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.List;
import java.util.Map;
import org.freedonia.bloodhound.server.findings.FindingPayload;

public record JobResultRequest(
        @NotBlank String workerId,
        List<FindingPayload> findings,
        Map<String, Object> rawMetadata,
        List<String> logLines) {}
