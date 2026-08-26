package org.freedonia.bloodhound.server.scim;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.server.scim.dto.ScimPatchOperation;
import org.junit.jupiter.api.Test;

/**
 * Real, documented IdP request shapes - not guesses. Azure AD's
 * activate/deactivate PATCH format is documented at
 * https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups
 * ("Update {"Operations":[{"op":"Replace","path":"active","value":false}]}").
 */
class ScimPatchProcessorTest {

    @Test
    void azureAdDeactivate_pathQualifiedReplace() {
        var ops = List.of(new ScimPatchOperation("Replace", "active", Boolean.FALSE));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.active()).isFalse();
        assertThat(plan.userName()).isNull();
        assertThat(plan.displayName()).isNull();
    }

    @Test
    void azureAdReactivate_lowercaseOpAndPath() {
        var ops = List.of(new ScimPatchOperation("replace", "active", Boolean.TRUE));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.active()).isTrue();
    }

    @Test
    void oktaStyle_pathLessValueMap() {
        // Some SCIM clients (including some Okta configurations) omit `path` and send a map of
        // attribute -> value directly in `value` for a bulk replace.
        var ops = List.of(new ScimPatchOperation(
                "replace", null, java.util.Map.of("active", false, "userName", "new@example.com")));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.active()).isFalse();
        assertThat(plan.userName()).isEqualTo("new@example.com");
    }

    @Test
    void givenNameFamilyNameBothTouched_combinesFresh() {
        var ops = List.of(
                new ScimPatchOperation("replace", "name.givenName", "Janet"),
                new ScimPatchOperation("replace", "name.familyName", "Smith"));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.displayName()).isEqualTo("Janet Smith");
    }

    @Test
    void onlyGivenNameTouched_preservesExistingFamilyName() {
        var ops = List.of(new ScimPatchOperation("replace", "name.givenName", "Janet"));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.displayName()).isEqualTo("Janet Doe");
    }

    @Test
    void explicitDisplayNameWins_overNameParts() {
        var ops = List.of(new ScimPatchOperation("replace", "displayName", "Custom Name"));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.displayName()).isEqualTo("Custom Name");
    }

    @Test
    void unrecognizedPath_ignoredNotRejected() {
        var ops = List.of(new ScimPatchOperation("replace", "emails[type eq \"work\"].value", "x@example.com"));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.isEmpty()).isTrue();
    }

    @Test
    void removeOp_ignored() {
        var ops = List.of(new ScimPatchOperation("remove", "active", null));
        ScimPatchPlan plan = ScimPatchProcessor.apply(ops, "Jane Doe");

        assertThat(plan.isEmpty()).isTrue();
    }

    @Test
    void emptyOperations_yieldsEmptyPlan() {
        assertThat(ScimPatchProcessor.apply(List.of(), "Jane Doe").isEmpty()).isTrue();
        assertThat(ScimPatchProcessor.apply(null, "Jane Doe").isEmpty()).isTrue();
    }
}
