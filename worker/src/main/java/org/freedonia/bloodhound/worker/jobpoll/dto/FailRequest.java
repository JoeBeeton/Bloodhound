package org.freedonia.bloodhound.worker.jobpoll.dto;

public record FailRequest(String workerId, String errorDetail) {}
