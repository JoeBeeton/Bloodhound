package org.freedonia.bloodhound.worker.jobpoll.dto;

import java.util.Map;

/** Wire shape of one reported finding. Mirrors central-server's own FindingPayload - two copies of one contract, not a shared type. */
public record FindingPayload(
        String ruleId,
        String severity,
        String category,
        String title,
        String description,
        String affectedAsset,
        Map<String, Object> evidence) {}
