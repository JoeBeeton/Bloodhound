package org.freedonia.bloodhound.server.scim.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** value is deliberately untyped (Object) - Jackson hands back Boolean/String/Map depending on what the client actually sent. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimPatchOperation(String op, String path, Object value) {}
