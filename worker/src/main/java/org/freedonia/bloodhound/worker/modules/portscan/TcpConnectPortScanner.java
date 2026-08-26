package org.freedonia.bloodhound.worker.modules.portscan;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Pure-Java Tier 1 light scan: a concurrent connect attempt per port against
 * a curated port list. No external CLI tool involved at all - a prior
 * revision shelled out to a third-party scanner for this, but that tool's
 * license was incompatible with releasing Bloodhound under Apache-2.0, and
 * this narrow case (no version detection, no scripts - just "is this port
 * open") never needed anything beyond a plain TCP connect anyway.
 */
public class TcpConnectPortScanner {

    /** Exact curated list from the plan - deliberately not expanded. */
    static final List<Integer> CURATED_PORTS = List.of(
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1433, 1521, 27017, 2375,
            2376, 3306, 3389, 5432, 5900, 5984, 6379, 8080, 8443, 8500, 9200, 9300, 9092, 27018);

    private static final int CONNECT_TIMEOUT_MS = 2000;
    private static final int POOL_SIZE = 20;
    private static final long HARD_TIMEOUT_SECONDS = 60;

    public List<Integer> scan(String hostname) throws ScanModuleException {
        InetAddress address = resolve(hostname);

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

    /**
     * Resolved once and the same InetAddress reused for all 35 connect
     * attempts (rather than each Socket resolving the hostname itself),
     * both to avoid redundant DNS lookups and so the safety check below
     * covers every attempt made by this scan - not just the first.
     */
    private InetAddress resolve(String hostname) throws ScanModuleException {
        try {
            InetAddress address = InetAddress.getByName(hostname);
            if (SafeAddressValidator.isUnsafeToConnect(address)) {
                throw new ScanModuleException(
                        hostname + " resolves to a private/loopback/reserved address - refusing to connect");
            }
            return address;
        } catch (UnknownHostException e) {
            throw new ScanModuleException(hostname + " could not be resolved", e);
        }
    }
}
