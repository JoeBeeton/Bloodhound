package org.freedonia.bloodhound.common.net;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;

class SafeAddressValidatorTest {

    private static InetAddress ip(String literal) throws UnknownHostException {
        return InetAddress.getByName(literal);
    }

    @Test
    void publicIpv4_safe() throws Exception {
        assertTrue(SafeAddressValidator.isSafeToConnect(ip("8.8.8.8")));
    }

    @Test
    void privateIpv4_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("10.0.0.1")));
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("192.168.1.1")));
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("172.16.0.1")));
    }

    @Test
    void loopbackIpv4_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("127.0.0.1")));
    }

    @Test
    void linkLocalIpv4Metadata_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("169.254.169.254")));
    }

    @Test
    void cgnatIpv4_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("100.64.0.1")));
    }

    @Test
    void thisNetworkIpv4_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("0.1.2.3")));
    }

    @Test
    void publicIpv6_safe() throws Exception {
        // Google Public DNS
        assertTrue(SafeAddressValidator.isSafeToConnect(ip("2001:4860:4860::8888")));
    }

    @Test
    void ipv6UniqueLocalAddress_unsafe() throws Exception {
        // fd00::/8 - the real-world-common half of the fc00::/7 ULA range - and the
        // regression case for the SSRF-guard gap this test class exists to close:
        // Inet6Address.isSiteLocalAddress() does NOT recognize this range.
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("fd12:3456:789a::1")));
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("fd00::1")));
    }

    @Test
    void ipv6UniqueLocalAddress_fc00Half_alsoUnsafe() throws Exception {
        // The other half of fc00::/7 (the "locally assigned" bit unset) - less common
        // in practice than fd00::/8 but still within the blocked range.
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("fc00::1")));
    }

    @Test
    void ipv6JustBelowUlaRange_stillSafe() throws Exception {
        // fb00::1 - one below fc00::/7's start (0xFC) - must NOT be caught by the new
        // check, confirming the (first & 0xFE) == 0xFC mask is exact, not overbroad.
        assertTrue(SafeAddressValidator.isSafeToConnect(ip("fbff::1")));
    }

    @Test
    void ipv6JustAboveUlaRange_stillSafe() throws Exception {
        // fe00::1 - one above fc00::/7's end (0xFD) - must NOT be caught either.
        assertTrue(SafeAddressValidator.isSafeToConnect(ip("fe00::1")));
    }

    @Test
    void ipv6DeprecatedSiteLocal_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("fec0::1")));
    }

    @Test
    void ipv6LinkLocal_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("fe80::1")));
    }

    @Test
    void ipv6Loopback_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("::1")));
    }

    @Test
    void ipv6Multicast_unsafe() throws Exception {
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("ff02::1")));
    }

    @Test
    void ipv4MappedIpv6PrivateLiteral_normalizedAndUnsafe() throws Exception {
        // The JDK normalizes this to an Inet4Address before it ever reaches this
        // validator, so it correctly hits the IPv4 branch rather than slipping past
        // both address-family checks.
        assertFalse(SafeAddressValidator.isSafeToConnect(ip("::ffff:10.0.0.1")));
    }

    @Test
    void requireSafeIfResolvable_ipv6UlaLiteral_throws() {
        assertThrows(IOException.class, () -> SafeAddressValidator.requireSafeIfResolvable("fd00::1"));
    }

    // parseAllowlist coverage - the actual env-var-to-static-field wiring (BLOODHOUND_SSRF_
    // ALLOWLIST -> ALLOWLISTED_HOSTNAMES, read once at class load) isn't exercised here since
    // that would need a real env var set before this JVM starts; live-verified instead (see the
    // network-segmentation/docker-compose commit) against the actual dev-fixtures juiceshop.local
    // scenario this allowlist exists for.

    @Test
    void parseAllowlist_nullOrBlank_producesEmptySet() {
        assertTrue(SafeAddressValidator.parseAllowlist(null).isEmpty());
        assertTrue(SafeAddressValidator.parseAllowlist("").isEmpty());
        assertTrue(SafeAddressValidator.parseAllowlist("   ").isEmpty());
    }

    @Test
    void parseAllowlist_singleHostname_normalizedToLowercase() {
        assertTrue(SafeAddressValidator.parseAllowlist("Juiceshop.Local").contains("juiceshop.local"));
    }

    @Test
    void parseAllowlist_multipleHostnames_trimmedAndSplit() {
        var result = SafeAddressValidator.parseAllowlist(" juiceshop.local , other.internal ,,  ");
        assertTrue(result.contains("juiceshop.local"));
        assertTrue(result.contains("other.internal"));
        assertTrue(result.size() == 2, "blank entries from doubled/trailing commas must not become empty-string entries");
    }
}
