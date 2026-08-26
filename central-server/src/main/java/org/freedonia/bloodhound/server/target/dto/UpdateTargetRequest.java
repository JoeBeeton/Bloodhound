package org.freedonia.bloodhound.server.target.dto;

/** Partial update - null fields are left unchanged. */
public record UpdateTargetRequest(Integer scanCadenceSeconds, Boolean isActive) {}
