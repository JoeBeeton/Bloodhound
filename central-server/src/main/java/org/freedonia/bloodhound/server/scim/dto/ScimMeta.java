package org.freedonia.bloodhound.server.scim.dto;

public record ScimMeta(String resourceType, String created, String lastModified, String location) {}
