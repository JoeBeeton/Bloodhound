package org.freedonia.bloodhound.worker.modules.fingerprint;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Pure interpretation of WordPress's REST API discovery document
 * ({@code /wp-json/}'s root response) into a plugin list - no fetch work
 * here, unit-testable against canned JSON. The document's top-level
 * {@code namespaces} array lists every REST namespace the site has
 * registered; third-party plugins near-universally register their own
 * namespace (their own public documentation says so - that's the whole
 * point of a namespace, avoiding collisions), so this is a reliable presence
 * signal even on installs that strip every other WordPress fingerprint
 * (confirmed live: no generator tag, no wp-content/wp-includes references
 * anywhere in the page, yet /wp-json/ still openly listed four installed
 * plugins by name).
 *
 * <p>Deliberately a small, curated, high-confidence map rather than an
 * attempt to catalog every plugin's namespace - getting one wrong here means
 * silently reporting a plugin that isn't installed, worse than not reporting
 * one that is. Core WordPress namespaces (ship with WordPress itself, not a
 * plugin) are explicitly excluded, not just "unrecognized and skipped", so
 * it's clear they were considered and deliberately left out.
 */
public final class WordPressRestApiDecisionLogic {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Ships with WordPress core itself - never a plugin, must never be reported as one. */
    private static final java.util.Set<String> CORE_NAMESPACES =
            java.util.Set.of("oembed/1.0", "wp/v2", "wp-site-health/v1", "wp-block-editor/v1");

    private static final Map<String, String> NAMESPACE_TO_PLUGIN = Map.ofEntries(
            Map.entry("yoast/v1", "Yoast SEO"),
            Map.entry("wordfence/v1", "Wordfence Security"),
            Map.entry("redirection/v1", "Redirection"),
            Map.entry("regenerate-thumbnails/v1", "Regenerate Thumbnails"),
            Map.entry("jetpack/v4", "Jetpack"),
            Map.entry("elementor/v1", "Elementor"),
            Map.entry("acf/v3", "Advanced Custom Fields"),
            Map.entry("wpforms/v1", "WPForms"),
            Map.entry("wc/v1", "WooCommerce"),
            Map.entry("wc/v2", "WooCommerce"),
            Map.entry("wc/v3", "WooCommerce"));

    private WordPressRestApiDecisionLogic() {}

    public static java.util.List<Technology> decide(String wpJsonBody) {
        if (wpJsonBody == null || wpJsonBody.isBlank()) {
            return java.util.List.of();
        }
        JsonNode root;
        try {
            root = MAPPER.readTree(wpJsonBody);
        } catch (Exception e) {
            return java.util.List.of();
        }
        JsonNode namespaces = root.path("namespaces");
        if (!namespaces.isArray()) {
            return java.util.List.of();
        }

        Map<String, Technology> found = new LinkedHashMap<>();
        for (JsonNode ns : namespaces) {
            String namespace = ns.asText(null);
            if (namespace == null || CORE_NAMESPACES.contains(namespace)) {
                continue;
            }
            String pluginName = NAMESPACE_TO_PLUGIN.get(namespace);
            if (pluginName != null) {
                String name = "WordPress Plugin: " + pluginName;
                found.putIfAbsent(name, new Technology(name, Technology.CMS, null));
            }
        }
        return java.util.List.copyOf(found.values());
    }
}
