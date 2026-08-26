package org.freedonia.bloodhound.server.scim;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.freedonia.bloodhound.server.scim.dto.ScimPatchOperation;

/**
 * Pure RFC 7644 3.5.2 PATCH interpreter for the attributes real IdP provisioning flows actually
 * touch: active, userName, name.givenName/familyName, displayName. "replace" and "add" are treated
 * identically for these single-valued attributes (both just set the value - there's no meaningful
 * difference for a scalar). Unsupported/unrecognized paths are silently ignored rather than
 * rejected, per RFC 7644's general tolerance for extension attributes a server doesn't implement -
 * a client patching an attribute Bloodhound doesn't model shouldn't fail the whole request.
 *
 * <p>Handles both the documented common case (Azure AD's path-qualified single-attribute form,
 * {"op":"replace","path":"active","value":false}) and the path-less form some SCIM clients use for
 * bulk attribute updates ({"op":"replace","value":{"active":false,"userName":"..."}}), where value
 * is a map of attribute name to new value.
 */
public final class ScimPatchProcessor {

    private ScimPatchProcessor() {}

    public static ScimPatchPlan apply(List<ScimPatchOperation> operations, String currentDisplayName) {
        if (operations == null || operations.isEmpty()) {
            return ScimPatchPlan.EMPTY;
        }
        Boolean active = null;
        String userName = null;
        String givenName = null;
        String familyName = null;
        String explicitDisplayName = null;
        boolean nameTouched = false;

        for (ScimPatchOperation op : operations) {
            if (op.op() == null || !("replace".equalsIgnoreCase(op.op()) || "add".equalsIgnoreCase(op.op()))) {
                continue;
            }
            if (op.path() == null || op.path().isBlank()) {
                if (op.value() instanceof Map<?, ?> attrs) {
                    for (Map.Entry<?, ?> entry : attrs.entrySet()) {
                        String key = String.valueOf(entry.getKey());
                        Object value = entry.getValue();
                        if ("active".equalsIgnoreCase(key)) {
                            active = coerceBoolean(value);
                        } else if ("username".equalsIgnoreCase(key)) {
                            userName = value == null ? null : String.valueOf(value);
                        } else if ("displayname".equalsIgnoreCase(key)) {
                            explicitDisplayName = value == null ? null : String.valueOf(value);
                        }
                    }
                }
                continue;
            }
            String path = op.path().toLowerCase(Locale.ROOT);
            switch (path) {
                case "active" -> active = coerceBoolean(op.value());
                case "username" -> userName = op.value() == null ? null : String.valueOf(op.value());
                case "displayname" -> explicitDisplayName = op.value() == null ? null : String.valueOf(op.value());
                case "name.givenname" -> {
                    givenName = op.value() == null ? "" : String.valueOf(op.value());
                    nameTouched = true;
                }
                case "name.familyname" -> {
                    familyName = op.value() == null ? "" : String.valueOf(op.value());
                    nameTouched = true;
                }
                default -> {
                    // Unrecognized/unsupported attribute path - intentionally ignored, see class Javadoc.
                }
            }
        }

        String displayName = explicitDisplayName;
        if (displayName == null && nameTouched) {
            String[] currentParts = splitCurrent(currentDisplayName);
            String finalGiven = givenName != null ? givenName : currentParts[0];
            String finalFamily = familyName != null ? familyName : currentParts[1];
            displayName = (finalGiven + " " + finalFamily).trim();
        }

        return new ScimPatchPlan(active, userName, displayName);
    }

    private static String[] splitCurrent(String currentDisplayName) {
        if (currentDisplayName == null || currentDisplayName.isBlank()) {
            return new String[] {"", ""};
        }
        int space = currentDisplayName.indexOf(' ');
        return space < 0
                ? new String[] {currentDisplayName, ""}
                : new String[] {currentDisplayName.substring(0, space), currentDisplayName.substring(space + 1)};
    }

    private static Boolean coerceBoolean(Object value) {
        if (value instanceof Boolean b) {
            return b;
        }
        if (value instanceof String s) {
            return Boolean.parseBoolean(s);
        }
        return null;
    }
}
