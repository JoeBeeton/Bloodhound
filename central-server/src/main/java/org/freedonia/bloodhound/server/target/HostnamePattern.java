package org.freedonia.bloodhound.server.target;

import java.util.regex.Pattern;

/**
 * The one hostname-shape check this codebase uses at target/subdomain creation - a single shared
 * constant so {@link org.freedonia.bloodhound.server.target.dto.CreateTargetRequest}'s bean
 * validation, {@link TargetController}'s own imperative bulk-create check, and {@link
 * org.freedonia.bloodhound.server.subdomain.SubdomainController}'s manual-add check can never
 * drift from each other the way a security review found the last two already had: {@code
 * SubdomainController#add} accepted any string that merely equalled or ended with the target's
 * root domain, with no check that it was a well-formed hostname at all. {@code
 * SafeAddressValidator#requireSafeIfResolvable} treats "does not resolve" as safe, so a crafted
 * value like {@code central-server#.example.com} (where {@code URI} parses the host as just
 * {@code central-server}, dropping everything from {@code #} on as a fragment) slipped straight
 * through that guard and into a URL built from the raw string.
 */
public final class HostnamePattern {

    public static final String REGEX =
            "^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$";

    public static final Pattern PATTERN = Pattern.compile(REGEX);

    private HostnamePattern() {}
}
