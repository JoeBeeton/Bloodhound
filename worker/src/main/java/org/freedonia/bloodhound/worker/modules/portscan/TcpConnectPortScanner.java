package org.freedonia.bloodhound.worker.modules.portscan;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.worker.modules.common.DualStackResolver;

/**
 * Pure-Java Tier 1 light scan: a concurrent connect attempt per port against
 * a curated port list. No external CLI tool involved at all - a prior
 * revision shelled out to a third-party scanner for this, but that tool's
 * license was incompatible with releasing Bloodhound under Apache-2.0, and
 * this narrow case (no version detection, no scripts - just "is this port
 * open") never needed anything beyond a plain TCP connect anyway.
 *
 * <p>Dual-stack: resolves and scans one IPv4 and one IPv6 address (whichever
 * of each family the host has) independently, rather than letting the JVM's
 * default address-family preference silently pick just one - a target
 * exposing something different (or extra) over IPv6 was previously never
 * checked at all, exactly the blind spot the plan's IPv6-parity item called
 * out. If a host has multiple A or multiple AAAA records, only the first of
 * each is used - this mirrors what a single {@code InetAddress.getByName}
 * call always did before, just once per family instead of once overall.
 */
public class TcpConnectPortScanner {

    /** Exact curated list from the plan - deliberately not expanded. */
    static final List<Integer> CURATED_PORTS = List.of(
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 27017, 2375,
            2376, 3306, 3389, 5432, 5900, 5984, 6379, 8080, 8443, 8500, 9200, 9300, 9092, 27018, 11211);

    private static final int CONNECT_TIMEOUT_MS = 2000;
    private static final int POOL_SIZE = 20;
    private static final long HARD_TIMEOUT_SECONDS = 60;

    /** Keys are "IPv4"/"IPv6" - see {@link PortScanDecisionLogic#decide}, which consumes this shape directly. */
    public Map<String, List<Integer>> scan(String hostname) throws ScanModuleException {
        Map<String, List<Integer>> result = new LinkedHashMap<>();
        for (Map.Entry<String, InetAddress> entry : DualStackResolver.resolveOnePerFamily(hostname).entrySet()) {
            result.put(entry.getKey(), scanAddress(entry.getValue()));
        }
        return result;
    }

    private List<Integer> scanAddress(InetAddress address) {
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(POOL_SIZE, CURATED_PORTS.size()));
        try {
            List<Future<Integer>> futures = new ArrayList<>();
            for (int port : CURATED_PORTS) {
                futures.add(pool.submit(() -> tryConnect(address, port)));
            }
            List<Integer> openPorts = new ArrayList<>();
            for (Future<Integer> future : futures) {
                try {
                    Integer port = future.get(HARD_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    if (port != null) {
                        openPorts.add(port);
                    }
                } catch (Exception e) {
                    // Timed out, refused, or unreachable - this one port is treated as closed.
                }
            }
            openPorts.sort(Integer::compareTo);
            return openPorts;
        } finally {
            pool.shutdownNow();
        }
    }

    private Integer tryConnect(InetAddress address, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), CONNECT_TIMEOUT_MS);
            return port;
        } catch (Exception e) {
            return null;
        }
    }
}
