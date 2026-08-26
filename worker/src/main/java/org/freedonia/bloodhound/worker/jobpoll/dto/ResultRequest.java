package org.freedonia.bloodhound.worker.jobpoll.dto;

import java.util.List;
import java.util.Map;

public record ResultRequest(String workerId, List<FindingPayload> findings, Map<String, Object> rawMetadata) {}
