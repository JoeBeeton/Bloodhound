package org.freedonia.bloodhound.server.jobqueue.dto;

import jakarta.validation.constraints.NotBlank;

public record WorkerScopedRequest(@NotBlank String workerId) {}
