package org.freedonia.bloodhound.common.net;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;

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
 */
public final class SafeAddressValidator {

    private SafeAddressValidator() {}

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
        }
        return true;
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
}
