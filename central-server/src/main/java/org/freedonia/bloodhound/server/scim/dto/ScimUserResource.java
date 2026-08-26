package org.freedonia.bloodhound.server.scim.dto;

import java.time.format.DateTimeFormatter;
import java.util.List;
import org.freedonia.bloodhound.server.scim.ScimUserRow;

/**
 * RFC 7643 core User schema (the minimal, real-interoperability subset). name.givenName/familyName
 * is a best-effort split of the single `display_name` column this project stores (same
 * "best-effort, documented limitation" precedent as the DKIM-common-selector check elsewhere in
 * this codebase) - split on the first space; a one-word display name becomes an empty familyName,
 * and re-joining on write (see #combineDisplayName) is exact for anything that round-trips through
 * this same split, which covers the common real case.
 */
public record ScimUserResource(
        List<String> schemas,
        String id,
        String externalId,
        String userName,
        ScimName name,
        String displayName,
        boolean active,
        List<ScimEmail> emails,
        ScimMeta meta) {

    public static final String USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User";

    public static ScimUserResource from(ScimUserRow row, String baseUrl) {
        String created = row.createdAt().atOffset(java.time.ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
        String modified = row.updatedAt().atOffset(java.time.ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
        return new ScimUserResource(
                List.of(USER_SCHEMA),
                row.id().toString(),
                row.externalId(),
                row.userName(),
                splitName(row.displayName()),
                row.displayName(),
                row.active(),
                List.of(new ScimEmail(row.userName(), true)),
                new ScimMeta("User", created, modified, baseUrl + "/scim/v2/Users/" + row.id()));
    }

    static ScimName splitName(String displayName) {
        if (displayName == null || displayName.isBlank()) {
            return new ScimName("", "");
        }
        int space = displayName.indexOf(' ');
        return space < 0
                ? new ScimName(displayName, "")
                : new ScimName(displayName.substring(0, space), displayName.substring(space + 1));
    }

    /** Reverse of #splitName - prefers an explicit displayName if the caller sent one, else joins given+family. */
    public static String combineDisplayName(ScimName name, String displayName) {
        if (displayName != null && !displayName.isBlank()) {
            return displayName;
        }
        if (name == null) {
            return "";
        }
        String given = name.givenName() == null ? "" : name.givenName();
        String family = name.familyName() == null ? "" : name.familyName();
        String combined = (given + " " + family).trim();
        return combined.isEmpty() ? given : combined;
    }
}
