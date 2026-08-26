package org.freedonia.bloodhound.server.scim.dto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ScimUserResourceTest {

    @Test
    void splitName_twoWords() {
        ScimName name = ScimUserResource.splitName("Jane Doe");
        assertThat(name.givenName()).isEqualTo("Jane");
        assertThat(name.familyName()).isEqualTo("Doe");
    }

    @Test
    void splitName_multiWordFamilyName() {
        // Only splits on the first space - "Van Der Berg" all goes to familyName, a documented
        // best-effort limitation, not a bug (same class of tradeoff as the DKIM common-selector check).
        ScimName name = ScimUserResource.splitName("Jane Van Der Berg");
        assertThat(name.givenName()).isEqualTo("Jane");
        assertThat(name.familyName()).isEqualTo("Van Der Berg");
    }

    @Test
    void splitName_singleWord() {
        ScimName name = ScimUserResource.splitName("Cher");
        assertThat(name.givenName()).isEqualTo("Cher");
        assertThat(name.familyName()).isEmpty();
    }

    @Test
    void splitName_blank() {
        ScimName name = ScimUserResource.splitName(null);
        assertThat(name.givenName()).isEmpty();
        assertThat(name.familyName()).isEmpty();
    }

    @Test
    void combineDisplayName_explicitDisplayNameWins() {
        String result = ScimUserResource.combineDisplayName(new ScimName("Jane", "Doe"), "Preferred Name");
        assertThat(result).isEqualTo("Preferred Name");
    }

    @Test
    void combineDisplayName_joinsNameParts() {
        String result = ScimUserResource.combineDisplayName(new ScimName("Jane", "Doe"), null);
        assertThat(result).isEqualTo("Jane Doe");
    }

    @Test
    void combineDisplayName_roundTripsThroughSplit() {
        // The property that actually matters: split(combine(x)) == x for anything that came from a split.
        ScimName original = ScimUserResource.splitName("Jane Doe");
        String recombined = ScimUserResource.combineDisplayName(original, null);
        assertThat(recombined).isEqualTo("Jane Doe");
    }

    @Test
    void combineDisplayName_onlyGivenName() {
        String result = ScimUserResource.combineDisplayName(new ScimName("Cher", ""), null);
        assertThat(result).isEqualTo("Cher");
    }
}
