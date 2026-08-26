package org.freedonia.bloodhound.server.scim;

import java.util.List;
import java.util.Map;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Static SCIM discovery responses. Real IdP SCIM clients (Okta, Azure AD)
 * probe these during initial provisioning setup before touching /Users at
 * all - without them, IdP-side configuration can fail before any user
 * provisioning is even attempted.
 */
@RestController
@RequestMapping(value = "/scim/v2", produces = "application/scim+json")
@PreAuthorize("hasRole('SCIM')")
public class ScimDiscoveryController {

    @GetMapping("/ServiceProviderConfig")
    public Map<String, Object> serviceProviderConfig() {
        return Map.ofEntries(
                Map.entry("schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig")),
                Map.entry("patch", Map.of("supported", true)),
                Map.entry("bulk", Map.of("supported", false, "maxOperations", 0, "maxPayloadSize", 0)),
                Map.entry("filter", Map.of("supported", true, "maxResults", 200)),
                Map.entry("changePassword", Map.of("supported", false)),
                Map.entry("sort", Map.of("supported", false)),
                Map.entry("etag", Map.of("supported", false)),
                Map.entry(
                        "authenticationSchemes",
                        List.of(Map.of(
                                "type", "oauthbearertoken",
                                "name", "Bearer Token",
                                "description", "Per-organization SCIM bearer token, issued from Bloodhound's admin UI"))));
    }

    @GetMapping("/ResourceTypes")
    public List<Map<String, Object>> resourceTypes() {
        return List.of(Map.of(
                "schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:ResourceType"),
                "id", "User",
                "name", "User",
                "endpoint", "/Users",
                "schema", "urn:ietf:params:scim:schemas:core:2.0:User"));
    }

    @GetMapping("/Schemas")
    public List<Map<String, Object>> schemas() {
        return List.of(Map.of(
                "id", "urn:ietf:params:scim:schemas:core:2.0:User",
                "name", "User",
                "description", "Bloodhound user account",
                "attributes", List.of(
                        Map.of("name", "userName", "type", "string", "required", true, "multiValued", false, "mutability", "readWrite"),
                        Map.of("name", "displayName", "type", "string", "required", false, "multiValued", false, "mutability", "readWrite"),
                        Map.of("name", "active", "type", "boolean", "required", false, "multiValued", false, "mutability", "readWrite"))));
    }
}
