package org.freedonia.bloodhound.common.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * SSRF guard: is this resolved IP address something Bloodhound should ever be
 * allowed to connect to as part of scanning a "target"? Blocks loopback,
 * RFC1918 private ranges, link-local (which includes the 169.254.169.254
 * cloud-metadata address on AWS/GCP/Azure), multicast, the CGNAT range, IPv6
 * Unique Local Addresses (fc00::/7 - see the dedicated check below, since
 * {@code isSiteLocalAddress()} does not cover this range), and the "any"
 * address - i.e. everything that isn't a normal publicly-routable host. Used
 * both at target/subdomain creation time (central-server) and
 * immediately before every outbound connection a scan module makes (worker),
 * since DNS is attacker-influenced and a hostname that resolved to a public
 * IP at creation time can be repointed at an internal address by scan time
 * (DNS rebinding) - the create-time check alone is not sufficient on its own.
 *
 * <p>{@code BLOODHOUND_SSRF_ALLOWLIST} (comma-separated hostnames, exact
 * match, case-insensitive) exists for exactly one real scenario: the bundled
 * `juiceshop.local` practice target (see docker-compose.yml's dev-fixtures
 * profile) inherently resolves to a private Docker-bridge address - that's
 * the whole point of it being a safe, self-contained thing to point Tier 2
 * active scanning at - so this guard would otherwise block the one target
 * it's explicitly safe to attack. Found live: every scan module failed
 * against it with "unreachable" after this guard was added to ZAP. Keyed by
 * hostname, not by IP range: a deployer opts a *specific, known* hostname
 * out, which is a fundamentally narrower hole than exempting a whole private
 * subnet (which would defeat this guard's purpose for every other target
 * that happens to resolve there). Empty by default - sets no exception for
 * any real deployment; only docker-compose.yml's own worker/central-server
 * environment blocks populate it, and only for the dev-fixtures hostname.
 */
public final class SafeAddressValidator {

    private static final Set<String> ALLOWLISTED_HOSTNAMES = parseAllowlist(System.getenv("BLOODHOUND_SSRF_ALLOWLIST"));

    private SafeAddressValidator() {}

    /** Package-visible so its parsing rules (trim, case-fold, drop blanks) are directly unit-testable without needing to fork a JVM with a real env var set. */
    static Set<String> parseAllowlist(String csv) {
        if (csv == null || csv.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toLowerCase(Locale.ROOT))
                .collect(Collectors.toUnmodifiableSet());
    }

    private static boolean isAllowlisted(String hostname) {
        return hostname != null && ALLOWLISTED_HOSTNAMES.contains(hostname.toLowerCase(Locale.ROOT));
    }

    /**
     * Public for callers that resolve a hostname themselves and filter addresses with {@link
     * #isUnsafeToConnect} directly (e.g. {@code DualStackResolver}, which needs one address per
     * IP family) rather than going through {@link #requireSafeIfResolvable}/{@link
     * #resolveSafeAddress} - those two already check the allowlist internally, but a caller
     * doing its own per-address filtering has no way to honor it otherwise. Found live:
     * PORT_SCAN_LIGHT/PORT_SCAN_DEEP against juiceshop.local (the allowlisted dev-fixtures
     * target) still failed with "resolves only to private/loopback/reserved addresses" despite
     * BLOODHOUND_SSRF_ALLOWLIST being set correctly - DualStackResolver was calling {@link
     * #isUnsafeToConnect} per-address with no hostname context at all, so the allowlist this
     * class already had could never be consulted from there.
     */
    public static boolean isHostnameAllowlisted(String hostname) {
        return isAllowlisted(hostname);
    }

    public static boolean isSafeToConnect(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isMulticastAddress()
                || address.isAnyLocalAddress()) {
            return false;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            // 0.0.0.0/8 - "this network"
            if (first == 0) {
                return false;
            }
            // 100.64.0.0/10 - carrier-grade NAT (RFC 6598), not covered by
            // isSiteLocalAddress()'s RFC1918 check but not public either.
            if (first == 100 && second >= 64 && second <= 127) {
                return false;
            }
        }
        if (bytes.length == 16) {
            // fc00::/7 - IPv6 Unique Local Addresses (RFC 4193), almost always
            // seen in practice as fd00::/8. Inet6Address.isSiteLocalAddress()
            // only recognizes the deprecated RFC 1884 fec0::/10 range and does
            // NOT cover this - confirmed empirically against this project's
            // JDK (fd12:3456:789a::1 comes back isSiteLocalAddress()=false,
            // isLinkLocalAddress()=false). Without this explicit check, any
            // hostname whose AAAA record points at an internal ULA address
            // (misconfiguration, or attacker-controlled DNS rebinding) would
            // sail straight past this SSRF guard exactly the way an
            // un-checked RFC1918 IPv4 address would.
            int first = bytes[0] & 0xFF;
            if ((first & 0xFE) == 0xFC) {
                return false;
            }
            // A security review found IPv4-compatible IPv6 (the deprecated "::a.b.c.d" form, RFC
            // 4291) and NAT64 (RFC 6052's "64:ff9b::/96") both skip every IPv4 check above
            // entirely - the RFC1918/CGNAT/"this network" logic only runs for a 4-byte address,
            // and neither of these is one. Confirmed live, on this project's own JDK:
            // isSafeToConnect() returned true (safe!) for both "::127.0.0.1" and
            // "::169.254.169.254" - the latter being the AWS/GCP/Azure cloud metadata address, a
            // real path to IMDS credential theft on a cloud deployment via a crafted AAAA record.
            // IPv4-MAPPED ("::ffff:a.b.c.d") needs no handling here: confirmed live that
            // InetAddress.getByName parses that specific textual form directly into a 4-byte
            // Inet4Address, so it's already covered by the block above and never reaches this
            // 16-byte branch at all. Recursing into the unwrapped embedded address (rather than
            // duplicating the IPv4 checks here) means it inherits every one of them, including any
            // added later.
            byte[] embeddedIPv4 = embeddedIPv4Address(bytes);
            if (embeddedIPv4 != null) {
                try {
                    return isSafeToConnect(InetAddress.getByAddress(embeddedIPv4));
                } catch (UnknownHostException e) {
                    // getByAddress only validates the array length (4 or 16 bytes) - embeddedIPv4
                    // is always exactly 4, so this is unreachable in practice. Fails closed anyway.
                    return false;
                }
            }
        }
        return true;
    }

    /**
     * The last 4 bytes of {@code bytes} if it's a 16-byte IPv4-compatible address ("::a.b.c.d" -
     * the first 12 bytes all zero) or a NAT64 address ("64:ff9b::/96" - RFC 6052's well-known
     * prefix in the first 12 bytes, embedded IPv4 in the last 4) - null otherwise.
     */
    private static byte[] embeddedIPv4Address(byte[] bytes) {
        boolean allZeroPrefix = true;
        for (int i = 0; i < 12; i++) {
            if (bytes[i] != 0) {
                allZeroPrefix = false;
                break;
            }
        }
        if (allZeroPrefix) {
            return Arrays.copyOfRange(bytes, 12, 16);
        }
        boolean nat64Prefix = (bytes[0] & 0xFF) == 0x00
                && (bytes[1] & 0xFF) == 0x64
                && (bytes[2] & 0xFF) == 0xFF
                && (bytes[3] & 0xFF) == 0x9B
                && bytes[4] == 0
                && bytes[5] == 0
                && bytes[6] == 0
                && bytes[7] == 0
                && bytes[8] == 0
                && bytes[9] == 0
                && bytes[10] == 0
                && bytes[11] == 0;
        return nat64Prefix ? Arrays.copyOfRange(bytes, 12, 16) : null;
    }

    public static boolean isUnsafeToConnect(InetAddress address) {
        return !isSafeToConnect(address);
    }

    /**
     * Resolves {@code hostname} and throws if any resolved address is unsafe
     * to connect to. Shared by every call site that needs this exact check
     * (central-server's target-creation guard, worker's HostFanOut /
     * BudgetedSequentialFanOut / DanglingCnameChecker) so the resolve+check
     * logic itself lives in exactly one place. An unresolvable hostname is
     * NOT an error here - callers that want "must resolve" semantics check
     * that separately; this method only ever rejects a hostname that
     * resolves to somewhere unsafe.
     */
    public static void requireSafeIfResolvable(String hostname) throws IOException {
        if (isAllowlisted(hostname)) {
            return;
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(hostname);
        } catch (UnknownHostException e) {
            return;
        }
        for (InetAddress address : addresses) {
            if (isUnsafeToConnect(address)) {
                throw new IOException(
                        hostname + " resolves to a private/loopback/reserved address - refusing to connect");
            }
        }
    }

    /**
     * Resolves {@code hostname} once and returns the specific address a caller should then
     * connect to directly, instead of handing back a bare "yes it's currently fine" and letting
     * the caller re-resolve independently at connect time - a security review flagged that
     * exact gap: {@code requireSafeIfResolvable} followed by a separate hostname-based {@code
     * InetSocketAddress}/socket connect leaves a real window for DNS rebinding to swap in an
     * unsafe address between the two resolutions. Used by every raw-socket connect in this
     * codebase that can act on the resolved address itself (TlsFetcher, ExposedPathFetcher's
     * Redis probe) - not usable everywhere: {@code java.net.http.HttpClient} and other
     * higher-level clients resolve internally with no "connect to this exact address" hook
     * exposed, so {@code requireSafeIfResolvable}'s check-then-let-the-caller-reconnect shape
     * remains the only option there, a documented, accepted residual gap for those call sites.
     *
     * <p>Unlike {@code requireSafeIfResolvable} (which conservatively rejects a hostname if ANY
     * of its resolved addresses is unsafe, since a caller using an HttpClient can't control
     * which one gets used), this only needs to validate the ONE address it's about to hand back
     * - the same single-address resolution {@code InetAddress.getByName} and the raw socket
     * constructors these callers previously used were already implicitly relying on.
     */
    public static InetAddress resolveSafeAddress(String hostname) throws IOException {
        InetAddress address = InetAddress.getByName(hostname);
        if (!isAllowlisted(hostname) && isUnsafeToConnect(address)) {
            throw new IOException(hostname + " resolves to a private/loopback/reserved address - refusing to connect");
        }
        return address;
    }
}
