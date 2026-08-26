package org.freedonia.bloodhound.server.jobqueue.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

public record ClaimJobsRequest(@NotBlank String workerId, @Min(1) @Max(20) int capacity) {}
