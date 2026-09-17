package org.freedonia.bloodhound.worker.modules.common;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.scanmodule.HostUnreachableException;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Shared "resolve one address per family, SSRF-filtered" logic for the two
 * modules that connect to raw sockets against a specific IP rather than
 * letting {@code HttpClient}/DNS-name-based connections pick a family
 * themselves (see {@code TcpConnectPortScanner}, {@code DeepPortScanModule}) -
 * both previously called a single-address {@code InetAddress.getByName},
 * which silently scanned whichever family the JVM's default address-ordering
 * preferred and left the other family completely unchecked.
 */
public final class DualStackResolver {

    private DualStackResolver() {}

    /**
     * Resolves every address {@code hostname} has, keeps at most one per
     * family (first A, first AAAA - if a host round-robins across multiple
     * addresses of the same family, only the first is used, matching what a
     * single {@code InetAddress.getByName} call always did before), and
     * drops any address that fails {@link SafeAddressValidator} - checked
     * per-address, so a public address of one family isn't discarded just
     * because the host also happens to answer with a private/reserved
     * address of the other family. Fails only if not a single address of
     * either family turned out to be safe to connect to.
     *
     * <p>{@code hostname}'s own allowlist status ({@link
     * SafeAddressValidator#isHostnameAllowlisted}) is checked once, up front - a live bug found
     * PORT_SCAN_LIGHT/PORT_SCAN_DEEP still refusing to scan the allowlisted juiceshop.local dev
     * fixture (it only ever resolves to a private Docker-bridge address, exactly why it's
     * allowlisted at all) because this method filtered per-address with no hostname context,
     * never consulting the allowlist {@link SafeAddressValidator#requireSafeIfResolvable}/{@link
     * SafeAddressValidator#resolveSafeAddress} already honor.
     *
     * @return keys are "IPv4"/"IPv6", in the order the addresses were resolved
     */
    public static Map<String, InetAddress> resolveOnePerFamily(String hostname) throws ScanModuleException {
        InetAddress[] all;
        try {
            all = InetAddress.getAllByName(hostname);
        } catch (UnknownHostException e) {
            throw new HostUnreachableException(hostname + " could not be resolved", e);
        }

        boolean allowlisted = SafeAddressValidator.isHostnameAllowlisted(hostname);
        Map<String, InetAddress> result = new LinkedHashMap<>();
        for (InetAddress address : all) {
            String family = address instanceof Inet6Address ? "IPv6" : "IPv4";
            if (result.containsKey(family) || (!allowlisted && SafeAddressValidator.isUnsafeToConnect(address))) {
                continue;
            }
            result.put(family, address);
        }
        if (result.isEmpty()) {
            throw new ScanModuleException(
                    hostname + " resolves only to private/loopback/reserved addresses - refusing to connect");
        }
        return result;
    }
}
