package org.freedonia.bloodhound.server.scim.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** RFC 7644 3.5.2. Azure AD's deactivate call is {"Operations":[{"op":"replace","path":"active","value":false}]}. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ScimPatchRequest(List<String> schemas, @JsonProperty("Operations") List<ScimPatchOperation> operations) {}
