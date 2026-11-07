package org.freedonia.bloodhound.worker.modules.http;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Where a redirect's {@code Location} header actually sends a browser. The open-redirect check used
 * to ask only whether the probe marker appeared anywhere in the header, which flagged every
 * same-site redirect that kept the query string. In prod that was 12 of 12 findings: apex to
 * {@code www}, {@code /login?ReturnUrl=...}, and similar. The question here is whether the redirect's
 * host is the probe domain, resolved the way a browser resolves it.
 */
final class OpenRedirectLocation {

    private OpenRedirectLocation() {}

    /**
     * Resolves {@code location} against the URL that returned it, normalised as browsers do
     * (WHATWG URL parsing for http/https): leading and trailing control characters and spaces are
     * stripped, tabs and newlines inside are removed, and backslashes count as slashes. That last
     * rule is why {@code /\evil.example} is an off-site redirect in every browser. Null when the
     * value still can't be parsed.
     */
    static URI resolve(URI base, String location) {
        if (base == null || location == null) {
            return null;
        }
        String normalised = stripControlAndSpace(location).replace('\\', '/');
        if (normalised.isEmpty()) {
            return null;
        }
        try {
            return base.resolve(new URI(percentEncodeIllegal(normalised)));
        } catch (URISyntaxException | IllegalArgumentException e) {
            return null;
        }
    }

    /** True when the redirect lands on the probe domain or a subdomain of it. */
    static boolean pointsAtProbe(URI base, String location) {
        URI resolved = resolve(base, location);
        return resolved != null && hostWithin(hostOf(resolved), HttpHeaderFetcher.OPEN_REDIRECT_PROBE_MARKER);
    }

    /**
     * Whether the probe should follow this hop to see where the chain ends. Only redirects that
     * stay on the target's own site and still carry the probe value: an apex to {@code www} hop
     * hides the real application from a single-request probe. Off-site hops (an SSO provider, a
     * CDN) are not followed, so the probe never sends requests to third parties.
     */
    static boolean followable(URI next, String rootDomain, String probedHost) {
        if (next == null) {
            return false;
        }
        String scheme = next.getScheme() == null ? "" : next.getScheme().toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return false;
        }
        String host = hostOf(next);
        boolean sameSite = hostWithin(host, rootDomain) || hostWithin(host, probedHost);
        return sameSite
                && next.toString().toLowerCase(Locale.ROOT).contains(HttpHeaderFetcher.OPEN_REDIRECT_PROBE_MARKER);
    }

    /**
     * Lower-cased host without a trailing dot. Falls back to the raw authority, minus userinfo and
     * port, because {@link URI#getHost()} returns null for names it considers invalid (an
     * underscore, for one) that browsers still visit.
     */
    static String hostOf(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            String authority = uri.getRawAuthority();
            if (authority == null) {
                return null;
            }
            int at = authority.lastIndexOf('@');
            host = at >= 0 ? authority.substring(at + 1) : authority;
            if (!host.startsWith("[")) {
                int colon = host.indexOf(':');
                if (colon >= 0) {
                    host = host.substring(0, colon);
                }
            }
        }
        host = host.toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        return host;
    }

    private static boolean hostWithin(String host, String domain) {
        if (host == null || domain == null || domain.isBlank()) {
            return false;
        }
        String d = domain.toLowerCase(Locale.ROOT);
        while (d.endsWith(".")) {
            d = d.substring(0, d.length() - 1);
        }
        return host.equals(d) || host.endsWith("." + d);
    }

    private static String stripControlAndSpace(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && value.charAt(start) <= ' ') {
            start++;
        }
        while (end > start && value.charAt(end - 1) <= ' ') {
            end--;
        }
        StringBuilder out = new StringBuilder(end - start);
        for (int i = start; i < end; i++) {
            char c = value.charAt(i);
            if (c != '\t' && c != '\n' && c != '\r') {
                out.append(c);
            }
        }
        return out.toString();
    }

    /** java.net.URI rejects characters browsers accept (spaces, {@code |}, non-ASCII), so escape them first. */
    private static String percentEncodeIllegal(String value) {
        StringBuilder out = new StringBuilder(value.length());
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if (c > 0x20 && c < 0x7f && "\"<>^`{|}".indexOf(c) < 0) {
                out.append((char) c);
            } else {
                out.append('%').append(String.format("%02X", c));
            }
        }
        return out.toString();
    }
}
