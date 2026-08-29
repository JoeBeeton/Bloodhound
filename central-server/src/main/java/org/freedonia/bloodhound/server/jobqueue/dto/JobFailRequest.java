package org.freedonia.bloodhound.server.jobqueue.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.List;

public record JobFailRequest(@NotBlank String workerId, String errorDetail, List<String> logLines) {}
