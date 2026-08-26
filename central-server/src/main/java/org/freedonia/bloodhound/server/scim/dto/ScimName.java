package org.freedonia.bloodhound.server.scim.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Real clients also send `formatted` and sometimes `middleName`/`honorificPrefix` - ignored, not modeled. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimName(String givenName, String familyName) {}
