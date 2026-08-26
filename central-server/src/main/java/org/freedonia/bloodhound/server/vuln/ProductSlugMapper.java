package org.freedonia.bloodhound.server.vuln;

import java.util.Map;
import java.util.Optional;

/**
 * Maps a fingerprinted technology display name to NVD's CPE "product"
 * component. Deliberately small and only covers technologies the worker's
 * TechDecisionLogic actually captures a version for today (nginx, Apache,
 * PHP, WordPress) - there's no point mapping a technology whose version we
 * never extract. Only the product slug matters, not the vendor, since
 * {@link NvdClient} queries with a wildcard vendor - which is itself the
 * reason this mapping can stay this small and low-risk: getting a vendor
 * wrong (nginx's real NVD vendor is "f5", not "nginx" - discovered by
 * testing, not documentation) would have silently produced zero results
 * under an exact-match approach, but doesn't matter here.
 */
public final class ProductSlugMapper {

    private ProductSlugMapper() {}

    private static final Map<String, String> SLUGS = Map.of(
            "nginx", "nginx",
            "Apache", "http_server",
            "PHP", "php",
            "WordPress", "wordpress");

    public static Optional<String> slugFor(String technologyName) {
        return Optional.ofNullable(SLUGS.get(technologyName));
    }
}
