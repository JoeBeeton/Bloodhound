package org.freedonia.bloodhound.server.jobqueue.dto;

import jakarta.validation.constraints.NotBlank;

public record JobFailRequest(@NotBlank String workerId, String errorDetail) {}
