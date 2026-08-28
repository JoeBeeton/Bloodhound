package org.freedonia.bloodhound.worker.modules.nuclei;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Wraps the {@code nuclei} binary (MIT-licensed, ProjectDiscovery - same
 * prebuilt-binary install pattern as naabu/subfinder) via ProcessBuilder for
 * Tier 2's template-based vulnerability scanning. Same process-handling
 * pattern as every other subprocess wrapper in this codebase (concurrent
 * stderr drain, hard wall-clock timeout with forced destruction).
 *
 * <p>Given a bare hostname, not a URL: nuclei's own httpx-based target
 * probing handles the http/https scheme detection itself (confirmed live -
 * unlike ZAP's spider, which needed this codebase to do its own HTTPS-first/
 * HTTP-fallback dance, nuclei doesn't need that duplicated here). The
 * hostname (not a pre-resolved IP) is what nuclei actually needs, for
 * correct virtual-host/SNI/Host-header behavior against name-based virtual
 * hosting - unlike naabu/zgrab2, which operate at raw-IP granularity and so
 * get a pre-resolved, pre-validated address from {@code DualStackResolver}
 * upstream in {@code DeepPortScanModule}. That means the SSRF check DeepPortScanModule
 * gets "for free" from resolving once and reusing the address has to happen
 * here instead: unlike {@code ZapActiveScanModule} (where the actual
 * connection is made by the separate ZAP container, outside this codebase's
 * own address-validation path), nuclei runs as a direct subprocess of this
 * JVM with real outbound network access, so it needs the same {@link
 * SafeAddressValidator} gate every other direct-subprocess/HTTP-fetching
 * module in this codebase already has.
 *
 * <p>{@code -etags dos,fuzz} is a deliberate, explicit safety floor beyond
 * whatever nuclei's own default template selection already excludes -
 * denial-of-service and fuzzing-style templates are a different class of
 * intrusiveness than the vulnerability-confirmation probes this module
 * exists for, so they're excluded regardless of the authorization gate
 * Tier 2 already requires. {@code -t} points at the template corpus baked
 * into the worker image at build time (see the Dockerfile) rather than
 * letting nuclei fetch/update templates mid-scan - reproducible builds, and
 * no runtime dependency on GitHub being reachable during a scan.
 */
public class NucleiFetcher {

    // Live-verified against scanme.nmap.org: a full-corpus scan took 487s (81% of the
    // previous 600s budget) against a fairly simple two-service host - a busier real
    // target (more open ports/paths, more templates matching and triggering multi-request
    // extraction) could plausibly run longer, so this carries headroom above that
    // observed case rather than being tuned tight to it.
    private static final long HARD_TIMEOUT_SECONDS = 1200; // 20 minutes
    private static final String TEMPLATES_DIR = "/opt/nuclei-templates";

    public String scanJsonLines(String hostname) throws ScanModuleException {
        // hostname reaches here as "-target", hostname in argv below - ProcessBuilder(List<String>)
        // isn't shell-interpreted, so classic ';'/backtick shell injection isn't possible, but a value
        // starting with '-' would land right after -target as nuclei's own CLI parser sees it, which is
        // argument-injection territory rather than shell injection. Unlike a target's root hostname
        // (locked to a strict DNS-name regex at creation, see CreateTargetRequest), a *discovered*
        // subdomain reaching here (this module scans "root plus known subdomains") is explicitly NOT
        // validated the same way - see the identical caveat in DanglingCnameChecker/CloudBucketChecker/
        // NsTakeoverChecker. A leading '-' is invalid DNS-label syntax regardless, so rejecting it here
        // costs nothing legitimate and closes the gap at the one call site that actually matters.
        if (hostname.startsWith("-")) {
            throw new ScanModuleException("refusing to pass a hostname starting with '-' to nuclei: " + hostname);
        }
        try {
            SafeAddressValidator.requireSafeIfResolvable(hostname);
        } catch (java.io.IOException e) {
            throw new ScanModuleException(
                    hostname + " resolves to a private/loopback/reserved address - refusing to run nuclei", e);
        }

        ProcessBuilder pb = new ProcessBuilder(
                "nuclei",
                "-target", hostname,
                "-jsonl",
                "-silent",
                "-omit-raw",
                "-no-color",
                "-disable-update-check",
                "-t", TEMPLATES_DIR,
                "-etags", "dos,fuzz",
                "-timeout", "8",
                "-rate-limit", "50",
                "-c", "25",
                // -H, not a shell string: one argv element ("Name: Value"), identifies every
                // request nuclei's template engine fires the same way every other outbound
                // request this platform makes does - see ScanUserAgent.
                "-H", "User-Agent: " + ScanUserAgent.VALUE);
        Process process = null;
        try {
            final Process started = pb.start();
            process = started;
            Thread stderrDrain = new Thread(() -> {
                try {
                    started.getErrorStream().transferTo(OutputStream.nullOutputStream());
                } catch (java.io.IOException ignored) {
                }
            });
            stderrDrain.setDaemon(true);
            stderrDrain.start();
            String output = readAll(process.getInputStream());
            boolean finished = process.waitFor(HARD_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new ScanModuleException(
                        "nuclei scan of " + hostname + " exceeded the hard " + HARD_TIMEOUT_SECONDS + "s timeout");
            }
            return output;
        } catch (java.io.IOException e) {
            throw new ScanModuleException("failed to invoke nuclei for " + hostname, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanModuleException("nuclei scan of " + hostname + " was interrupted", e);
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    private String readAll(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        in.transferTo(out);
        return out.toString(StandardCharsets.UTF_8);
    }
}
