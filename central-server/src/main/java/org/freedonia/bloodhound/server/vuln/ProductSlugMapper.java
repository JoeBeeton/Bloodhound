package org.freedonia.bloodhound.server.vuln;

import java.util.Map;
import java.util.Optional;

/**
 * Maps a fingerprinted technology display name to NVD's CPE "product"
 * component. Deliberately small and only covers technologies the worker's
 * TechDecisionLogic actually captures a version for today (nginx, Apache,
 * PHP, WordPress, jQuery, Bootstrap, Drupal) - there's no point mapping a
 * technology whose version we never extract. Deliberately does NOT include
 * WordPress plugins/themes: TechDecisionLogic does capture versions for
 * those (see addWordPressPluginsAndThemes), but there are tens of thousands
 * of plugin slugs, and mapping them one at a time here doesn't scale the
 * way mapping a handful of platforms does - a real gap, not an oversight,
 * left for whoever tackles it as a properly-scoped piece of its own. Only
 * the product slug matters, not the vendor, since
 * {@link NvdClient} queries with a wildcard vendor - which is itself the
 * reason this mapping can stay this small and low-risk: getting a vendor
 * wrong (nginx's real NVD vendor is "f5", not "nginx" - discovered by
 * testing, not documentation) would have silently produced zero results
 * under an exact-match approach, but doesn't matter here. jQuery/Bootstrap/
 * Drupal's slugs below are standard, well-established CPE dictionary
 * entries, not independently verified against a live NVD query the way
 * nginx's was - worth confirming for real if CVE correlation for these
 * ever looks suspiciously empty.
 */
public final class ProductSlugMapper {

    private ProductSlugMapper() {}

    private static final Map<String, String> SLUGS = Map.of(
            "nginx", "nginx",
            "Apache", "http_server",
            "PHP", "php",
            "WordPress", "wordpress",
            "jQuery", "jquery",
            "Bootstrap", "bootstrap",
            "Drupal", "drupal");

    public static Optional<String> slugFor(String technologyName) {
        return Optional.ofNullable(SLUGS.get(technologyName));
    }
}
