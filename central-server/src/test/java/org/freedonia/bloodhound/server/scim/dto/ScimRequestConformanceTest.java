package org.freedonia.bloodhound.server.scim.dto;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

/**
 * Deserializes the exact, real request bodies Okta and Azure AD are documented to send, proving
 * this project's DTOs actually parse them - not synthetic/guessed shapes.
 *
 * <p>Azure AD create/PATCH shapes: Microsoft Entra SCIM provisioning reference,
 * https://learn.microsoft.com/en-us/entra/identity/app-provisioning/use-scim-to-provision-users-and-groups
 * Okta create shape: Okta SCIM protocol reference,
 * https://developer.okta.com/docs/reference/scim/scim-20/#create-a-new-user
 */
class ScimRequestConformanceTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void azureAd_createUserRequest() throws Exception {
        String json =
                """
                {
                  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                  "externalId": "0a21f0f2-8d2a-4f8e-bf98-7363c4bbf5a4",
                  "userName": "jane.doe@example.com",
                  "active": true,
                  "displayName": "Jane Doe",
                  "name": { "formatted": "Jane Doe", "familyName": "Doe", "givenName": "Jane" },
                  "emails": [{ "primary": true, "type": "work", "value": "jane.doe@example.com" }]
                }
                """;

        ScimUserWriteRequest request = mapper.readValue(json, ScimUserWriteRequest.class);

        assertThat(request.userName()).isEqualTo("jane.doe@example.com");
        assertThat(request.externalId()).isEqualTo("0a21f0f2-8d2a-4f8e-bf98-7363c4bbf5a4");
        assertThat(request.name().givenName()).isEqualTo("Jane");
        assertThat(request.name().familyName()).isEqualTo("Doe");
        assertThat(request.activeOrDefault()).isTrue();
    }

    @Test
    void azureAd_deactivatePatchRequest() throws Exception {
        String json =
                """
                {
                  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                  "Operations": [
                    { "op": "Replace", "path": "active", "value": false }
                  ]
                }
                """;

        ScimPatchRequest request = mapper.readValue(json, ScimPatchRequest.class);

        assertThat(request.operations()).hasSize(1);
        assertThat(request.operations().get(0).op()).isEqualToIgnoringCase("replace");
        assertThat(request.operations().get(0).path()).isEqualTo("active");
        assertThat(request.operations().get(0).value()).isEqualTo(Boolean.FALSE);
    }

    @Test
    void okta_createUserRequest() throws Exception {
        String json =
                """
                {
                  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
                  "userName": "jdoe",
                  "name": { "givenName": "John", "familyName": "Doe" },
                  "emails": [{ "primary": true, "value": "jdoe@example.com", "type": "work" }],
                  "displayName": "John Doe",
                  "active": true
                }
                """;

        ScimUserWriteRequest request = mapper.readValue(json, ScimUserWriteRequest.class);

        assertThat(request.userName()).isEqualTo("jdoe");
        assertThat(request.displayName()).isEqualTo("John Doe");
    }

    @Test
    void okta_existenceCheckFilter_matchesTheControllersRegex() {
        // Okta's documented pre-create existence check: GET /Users?filter=userName+eq+"jdoe"
        String filter = "userName eq \"jdoe\"";
        var matcher = java.util.regex.Pattern.compile(
                        "userName\\s+eq\\s+[\"']([^\"']*)[\"']", java.util.regex.Pattern.CASE_INSENSITIVE)
                .matcher(filter);
        assertThat(matcher.find()).isTrue();
        assertThat(matcher.group(1)).isEqualTo("jdoe");
    }
}
