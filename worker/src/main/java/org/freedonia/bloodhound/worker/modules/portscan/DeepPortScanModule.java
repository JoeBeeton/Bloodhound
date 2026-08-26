package org.freedonia.bloodhound.worker.modules.portscan;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.scanmodule.ModuleResult;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.common.scanmodule.ScanModule;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.freedonia.bloodhound.common.scanmodule.ScanTier;
import org.freedonia.bloodhound.worker.modules.common.PayloadSubdomains;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Tier 2: full-port-range discovery plus best-effort service identification
 * for a single host. Only ever dispatched via TargetController's
 * authorization-gated POST /targets/{id}/scan/deep - never part of the
 * normal Tier 1 scan run.
 *
 * <p>Three permissively-licensed, independently-invoked pieces: {@link
 * NaabuFetcher} (MIT) for the full 1-65535 port sweep, {@link Zgrab2Fetcher}
 * (Apache-2.0) for best-effort service identification on whatever's open,
 * and a hand-written {@link FtpAnonymousChecker} for an anonymous-FTP-login
 * probe specifically (zgrab2 has no such check built in). There's no
 * drop-in for a full protocol-fingerprinting script library or a
 * decades-accumulated service/version signature database - this is an
 * honest, narrower identification pass, not a feature-for-feature port of
 * every capability a heavier commercial-licensed scanner might offer.
 *
 * <p>ScanRunService#createDeepScan dispatches one job per host (root plus
 * known subdomains, capped) rather than one job carrying every host - so
 * this module just scans the single host named in its own job payload
 * ({@link PayloadSubdomains#singleHost}). Distributing across multiple
 * *hosts* now happens via the job queue's normal FOR UPDATE SKIP LOCKED
 * claiming (spread across however many workers are free), not by looping
 * inside one job on one worker.
 */
@Component
public class DeepPortScanModule implements ScanModule {

    private static final Logger log = LoggerFactory.getLogger(DeepPortScanModule.class);

    private static final Set<Integer> HTTP_PORTS = Set.of(80, 8080, 8000, 8888, 3000, 5000, 8081, 9000);
    private static final Set<Integer> HTTPS_PORTS = Set.of(443, 8443);
    private static final int IDENTIFY_POOL_SIZE = 8;
    private static final long PER_PORT_TIMEOUT_SECONDS = 20;
    private static final int FTP_PORT = 21;

    private final NaabuFetcher naabuFetcher = new NaabuFetcher();
    private final Zgrab2Fetcher zgrab2Fetcher = new Zgrab2Fetcher();

    @Override
    public String moduleType() {
        return "PORT_SCAN_DEEP";
    }

    @Override
    public ScanTier tier() {
        return ScanTier.TIER_2;
    }

    @Override
    public ModuleResult execute(ScanContext context) throws ScanModuleException {
        String host = PayloadSubdomains.singleHost(context);
        List<RawFinding> findings = scanOneHost(host);
        return new ModuleResult(findings, Map.of("host", host, "findingCount", findings.size()));
    }

    private List<RawFinding> scanOneHost(String hostname) throws ScanModuleException {
        InetAddress address = resolve(hostname);
        String ip = address.getHostAddress();

        List<Integer> openPorts = NaabuJsonParser.parseOpenPorts(naabuFetcher.fetchJsonLines(ip));
        List<PortDetail> details = identifyServices(ip, address, openPorts);
        return DeepPortScanDecisionLogic.decide(hostname, details);
    }

    private List<PortDetail> identifyServices(String ip, InetAddress address, List<Integer> openPorts) {
        if (openPorts.isEmpty()) {
            return List.of();
        }
        ExecutorService pool = Executors.newFixedThreadPool(Math.min(IDENTIFY_POOL_SIZE, openPorts.size()));
        try {
            List<Future<PortDetail>> futures = new ArrayList<>();
            for (int port : openPorts) {
                futures.add(pool.submit(() -> identifyOne(ip, address, port)));
            }
            List<PortDetail> details = new ArrayList<>();
            for (int i = 0; i < futures.size(); i++) {
                int port = openPorts.get(i);
                try {
                    details.add(futures.get(i).get(PER_PORT_TIMEOUT_SECONDS, TimeUnit.SECONDS));
                } catch (Exception e) {
                    log.debug("service identification for {}:{} skipped: {}", ip, port, e.getMessage());
                    details.add(new PortDetail(port, null, null, null, Map.of()));
                }
            }
            return details;
        } finally {
            pool.shutdownNow();
        }
    }

    private PortDetail identifyOne(String ip, InetAddress address, int port) {
        String serviceName = null;
        String serviceProduct = null;
        String serviceVersion = null;

        try {
            if (HTTP_PORTS.contains(port) || HTTPS_PORTS.contains(port)) {
                boolean tls = HTTPS_PORTS.contains(port);
                var server = Zgrab2JsonParser.parseHttpServerHeader(zgrab2Fetcher.httpJson(ip, port, tls));
                if (server.isPresent()) {
                    var guess = BannerDecisionLogic.fromHttpServerHeader(server.get());
                    serviceName = guess.name();
                    serviceProduct = guess.product();
                    serviceVersion = guess.version();
                } else {
                    serviceName = tls ? "https" : "http";
                }
            } else {
                var banner = Zgrab2JsonParser.parseBannerText(zgrab2Fetcher.bannerJson(ip, port));
                if (banner.isPresent()) {
                    var guess = BannerDecisionLogic.fromBanner(banner.get());
                    serviceName = guess.name();
                    serviceProduct = guess.product();
                    serviceVersion = guess.version();
                }
            }
        } catch (ScanModuleException e) {
            log.debug("zgrab2 identification of {}:{} failed: {}", ip, port, e.getMessage());
        }

        Map<String, String> scriptOutputs = new LinkedHashMap<>();
        if (port == FTP_PORT) {
            String anon = FtpAnonymousChecker.checkAnonymousLogin(address);
            if (anon != null) {
                scriptOutputs.put("ftp-anon", anon);
            }
        }

        return new PortDetail(port, serviceName, serviceProduct, serviceVersion, scriptOutputs);
    }

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
