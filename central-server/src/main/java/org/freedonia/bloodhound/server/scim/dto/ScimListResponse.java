package org.freedonia.bloodhound.server.scim.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record ScimListResponse(
        List<String> schemas,
        int totalResults,
        int itemsPerPage,
        int startIndex,
        @JsonProperty("Resources") List<ScimUserResource> resources) {

    public static final String LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse";

    public static ScimListResponse of(List<ScimUserResource> resources, int totalResults, int startIndex, int itemsPerPage) {
        return new ScimListResponse(List.of(LIST_SCHEMA), totalResults, itemsPerPage, startIndex, resources);
    }
}
