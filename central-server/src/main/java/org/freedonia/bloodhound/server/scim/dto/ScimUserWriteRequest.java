package org.freedonia.bloodhound.server.scim.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * POST (create) and PUT (full replace) both send this shape - id/meta/emails are server-computed,
 * not client-supplied. Real clients send additional fields this record doesn't model (schemas,
 * emails, name.formatted, etc.) - SCIM servers are expected to tolerate unrecognized attributes
 * rather than reject the request, per RFC 7643's general extensibility model.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimUserWriteRequest(
        String externalId, String userName, ScimName name, String displayName, Boolean active) {

    public boolean activeOrDefault() {
        return active == null || active;
    }
}
