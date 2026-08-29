package org.freedonia.bloodhound.worker.jobpoll.dto;

import java.util.List;

public record FailRequest(String workerId, String errorDetail, List<String> logLines) {}
