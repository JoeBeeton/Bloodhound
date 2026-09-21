package org.freedonia.bloodhound.server.eol;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Maps a fingerprinted technology display name to endoflife.date's own product slug -
 * the exact same scope as {@code vuln.ProductSlugMapper} (only technologies
 * TechDecisionLogic actually captures a version for today: nginx, Apache, PHP,
 * WordPress, jQuery, Bootstrap, Drupal), but a different mapping table, since
 * endoflife.date's slugs don't match NVD's CPE product names - e.g. Apache is
 * {@code http_server} on NVD but {@code apache-http-server} on endoflife.date. Every
 * slug below was confirmed to exist in endoflife.date's live product catalog while
 * scoping this feature (475 products total as of the check).
 */
public final class EolProductSlugMapper {

    private EolProductSlugMapper() {}

    private static final Map<String, String> SLUGS = Map.of(
            "nginx", "nginx",
            "Apache", "apache-http-server",
            "PHP", "php",
            "WordPress", "wordpress",
            "jQuery", "jquery",
            "Bootstrap", "bootstrap",
            "Drupal", "drupal");

    public static Optional<String> slugFor(String technologyName) {
        return Optional.ofNullable(SLUGS.get(technologyName));
    }

    /** Every technology display name this mapper knows a slug for - used to restrict fingerprint queries to technologies worth checking at all. */
    public static Set<String> knownTechnologyNames() {
        return SLUGS.keySet();
    }
}
