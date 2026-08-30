package org.freedonia.bloodhound.server.target.dto;

/** Partial update - null fields are left unchanged. notes is the one exception: a blank string is a deliberate clear, not a no-op - see TargetRepository#updateNotes. */
public record UpdateTargetRequest(Integer scanCadenceSeconds, Boolean isActive, String notes) {}
