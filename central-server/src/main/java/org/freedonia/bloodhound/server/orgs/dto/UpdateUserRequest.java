package org.freedonia.bloodhound.server.orgs.dto;

/** Partial update - null fields are left unchanged. */
public record UpdateUserRequest(String role, String status) {}
