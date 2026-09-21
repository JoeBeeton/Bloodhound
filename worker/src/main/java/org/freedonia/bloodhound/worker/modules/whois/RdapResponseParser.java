package org.freedonia.bloodhound.worker.modules.whois;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Pure parsing of RDAP JSON (the domain lookup response, and the IANA
 * bootstrap registry) - no network calls, fully unit-testable against canned
 * fixtures.
 */
public final class RdapResponseParser {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private RdapResponseParser() {}

    /** Finds the first RDAP base URL registered for {@code tld} in IANA's bootstrap file (https://data.iana.org/rdap/dns.json). */
    public static String findRdapBaseUrl(String bootstrapJson, String tld) {
        try {
            JsonNode root = MAPPER.readTree(bootstrapJson);
            String needle = tld.toLowerCase(java.util.Locale.ROOT);
            for (JsonNode service : root.path("services")) {
                if (service.size() < 2) {
                    continue;
                }
                for (JsonNode tldNode : service.get(0)) {
                    if (needle.equals(tldNode.asText().toLowerCase(java.util.Locale.ROOT))) {
                        JsonNode urls = service.get(1);
                        return urls.size() > 0 ? urls.get(0).asText() : null;
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /** Parses a standard RDAP domain-lookup response (RFC 9083). */
    public static WhoisFields parseDomainResponse(String json) {
        try {
            JsonNode root = MAPPER.readTree(json);
            Instant created = eventDate(root, "registration");
            Instant expiry = eventDate(root, "expiration");
            String registrar = registrarName(root);
            List<String> nameServers = new ArrayList<>();
            for (JsonNode ns : root.path("nameservers")) {
                String ldh = ns.path("ldhName").asText(null);
                if (ldh != null) {
                    nameServers.add(ldh.toLowerCase(java.util.Locale.ROOT));
                }
            }
            Map<String, Object> raw = MAPPER.convertValue(root, Map.class);
            List<String> statusCodes = new ArrayList<>();
            for (JsonNode status : root.path("status")) {
                statusCodes.add(status.asText());
            }
            return new WhoisFields(registrar, created, expiry, null, nameServers, raw, false, statusCodes);
        } catch (Exception e) {
            return WhoisFields.empty(false);
        }
    }

    private static Instant eventDate(JsonNode root, String action) {
        for (JsonNode event : root.path("events")) {
            if (action.equals(event.path("eventAction").asText())) {
                try {
                    return Instant.parse(event.path("eventDate").asText());
                } catch (Exception e) {
                    return null;
                }
            }
        }
        return null;
    }

    /** The registrar entity's display name lives in its vCard's "fn" property, per RDAP's vcardArray jCard encoding. */
    private static String registrarName(JsonNode root) {
        for (JsonNode entity : root.path("entities")) {
            boolean isRegistrar = false;
            for (JsonNode role : entity.path("roles")) {
                if ("registrar".equals(role.asText())) {
                    isRegistrar = true;
                }
            }
            if (!isRegistrar) {
                continue;
            }
            JsonNode vcardArray = entity.path("vcardArray");
            if (vcardArray.size() < 2) {
                continue;
            }
            for (JsonNode property : vcardArray.get(1)) {
                if (property.size() >= 4 && "fn".equals(property.get(0).asText())) {
                    return property.get(3).asText();
                }
            }
        }
        return null;
    }
}
