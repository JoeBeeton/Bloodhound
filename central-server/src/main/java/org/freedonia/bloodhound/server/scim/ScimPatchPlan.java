package org.freedonia.bloodhound.server.scim;

/** Null fields mean "not touched by this PATCH" - distinct from an explicit empty-string write. */
public record ScimPatchPlan(Boolean active, String userName, String displayName) {

    public static final ScimPatchPlan EMPTY = new ScimPatchPlan(null, null, null);

    public boolean isEmpty() {
        return active == null && userName == null && displayName == null;
    }
}
