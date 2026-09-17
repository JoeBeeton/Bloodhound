package org.freedonia.bloodhound.worker.modules.nuclei;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.freedonia.bloodhound.common.net.SafeAddressValidator;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
import org.freedonia.bloodhound.common.scanmodule.HostUnreachableException;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

    private static final Logger log = LoggerFactory.getLogger(NucleiFetcher.class);

    // Live-verified against scanme.nmap.org: a full-corpus scan took 487s (81% of the
    // previous 600s budget) against a fairly simple two-service host - a busier real
    // target (more open ports/paths, more templates matching and triggering multi-request
    // extraction) could plausibly run longer, so this carries headroom above that
    // observed case rather than being tuned tight to it.
    private static final long HARD_TIMEOUT_SECONDS = 1200; // 20 minutes
    private static final String TEMPLATES_DIR = "/opt/nuclei-templates";

    /**
     * A security review found this had the same two bugs already fixed in Zgrab2Fetcher this
     * session: readAll() had no size cap at all, AND it ran BEFORE
     * process.waitFor(HARD_TIMEOUT_SECONDS) - a nuclei child process hung without closing stdout
     * blocked this forever, and the "hard timeout" never got a chance to run. Same watchdog fix:
     * a shared daemon ScheduledExecutorService force-destroys the process after the deadline,
     * which (unlike Thread.interrupt()) reliably unblocks a thread stuck reading its stdout pipe.
     * Generous relative to Zgrab2Fetcher's own 1MB cap - a full-corpus template scan producing
     * many real findings (each a JSONL line) can legitimately be larger than one zgrab2 probe's
     * single-target banner/header capture.
     */
    private static final int MAX_OUTPUT_BYTES = 10_000_000;

    /**
     * nuclei's fatal errors ("FTL Could not run nuclei: ...") go to stderr, and it exits 1 without
     * writing a single JSONL line. This used to be drained straight to nullOutputStream and the exit
     * code never checked, so a nuclei that couldn't even start looked identical to a clean scan
     * with nothing to report - which is exactly how a template-directory permission regression
     * (see the Dockerfile) went unnoticed for two weeks of "0 findings" scans. Keeping the last
     * few KB of stderr is enough to put the real reason in the job's error_detail.
     */
    private static final int STDERR_TAIL_BYTES = 4096;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "nuclei-watchdog");
        thread.setDaemon(true);
        return thread;
    });

    /**
     * A live incident found several genuinely-dead subdomains (connection attempts that hang for
     * ~5s before failing, rather than a fast refusal) each burning the full HARD_TIMEOUT_SECONDS
     * (20 minutes) with zero output, worker capacity gone the entire time: nuclei's own template
     * corpus is large enough (10,000+ templates) that even with -c 25 concurrency, a host where
     * every single request takes the full connect timeout to fail can plausibly exceed the hard
     * timeout before nuclei's built-in -max-host-error safety valve (default 30, confirmed still
     * enabled here) has a chance to kick in - confirmed live: re-ran nuclei directly against one
     * of these hosts with -mhe lowered to 10 and it still produced zero output after 2 real
     * minutes, so that flag alone isn't a reliable fix for this specific failure shape. A single
     * fast reachability probe first (the same HTTPS-first/HTTP-fallback shape HttpHeaderFetcher/
     * ZapScanRunner already use to answer exactly this question) turns a worst-case 20-minute
     * dead-host job into a few-second one, freeing that worker slot back to the queue - directly
     * relevant to overall scan throughput/fairness, not just this one module's own runtime.
     */
    private static final Duration REACHABILITY_TIMEOUT = Duration.ofSeconds(6);

    private final HttpClient reachabilityClient = HttpClient.newBuilder()
            .connectTimeout(REACHABILITY_TIMEOUT)
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private void requireReachable(String hostname) throws ScanModuleException {
        try {
            SafeHttpGet.get(reachabilityClient, "https://" + hostname + "/", REACHABILITY_TIMEOUT,
                    ScanUserAgent.VALUE, HttpResponse.BodyHandlers.discarding(), 5);
        } catch (Exception httpsFailure) {
            try {
                SafeHttpGet.get(reachabilityClient, "http://" + hostname + "/", REACHABILITY_TIMEOUT,
                        ScanUserAgent.VALUE, HttpResponse.BodyHandlers.discarding(), 5);
            } catch (Exception httpFailure) {
                throw new HostUnreachableException(hostname + " is unreachable over HTTPS or HTTP - skipping the "
                        + "nuclei scan rather than spending its full timeout budget probing a dead host", httpFailure);
            }
        }
    }

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
        requireReachable(hostname);

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
                // A security review found nuclei's full template corpus includes OAST/blind-
                // injection templates that, absent this flag, auto-provision a random subdomain on
                // ProjectDiscovery's own public Interactsh servers (oast.pro/oast.fun/etc.) and poll
                // it for callbacks - meaning every deep scan run against a real, possibly sensitive
                // customer target was silently sending that target's hostname/IP association to a
                // third party. -no-interactsh disables OAST-based detection entirely rather than
                // pointing at a self-hosted instance (a real follow-up, but a new always-on service
                // this stack would need to run and keep reachable from the worker - out of scope for
                // closing the actual leak here).
                "-no-interactsh",
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
            StderrTail stderrTail = new StderrTail();
            Thread stderrDrain = new Thread(() -> {
                try {
                    stderrTail.drain(started.getErrorStream());
                } catch (IOException ignored) {
                }
            });
            stderrDrain.setDaemon(true);
            stderrDrain.start();
            AtomicBoolean timedOut = new AtomicBoolean(false);
            ScheduledFuture<?> deadline = WATCHDOG.schedule(
                    () -> {
                        timedOut.set(true);
                        started.destroyForcibly();
                    },
                    HARD_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS);
            String output;
            try {
                output = SafeHttpGet.readCappedUtf8(process.getInputStream(), MAX_OUTPUT_BYTES);
            } finally {
                deadline.cancel(false);
            }
            // Reap only - see Zgrab2Fetcher's identical comment for why this should return near-
            // instantly regardless of which path got here. The reaped check guards exitValue(),
            // which throws on a still-alive process.
            boolean reaped = process.waitFor(2, TimeUnit.SECONDS);
            if (timedOut.get()) {
                throw new ScanModuleException(
                        "nuclei scan of " + hostname + " exceeded the hard " + HARD_TIMEOUT_SECONDS + "s timeout");
            }
            // stderr is only consulted when nuclei produced nothing at all: a scan that emitted
            // real findings and then exited non-zero (a late template error, say) still has
            // findings worth ingesting. Blank output plus a non-zero exit is the "couldn't run"
            // case and must fail the job rather than masquerade as a clean scan.
            stderrDrain.join(2000);
            if (reaped && process.exitValue() != 0) {
                if (output.isBlank()) {
                    throw new ScanModuleException("nuclei exited " + process.exitValue() + " with no output for "
                            + hostname + ": " + stderrTail.text());
                }
                // Partial results are still ingested, but a run that died part-way must not look
                // like a clean one in the job log - this is what tells "few findings" apart from
                // "few findings because nuclei fell over halfway through".
                log.warn(
                        "nuclei exited {} after producing output for {} - ingesting partial results; stderr: {}",
                        process.exitValue(),
                        hostname,
                        stderrTail.text());
            }
            return output;
        } catch (IOException e) {
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

    /**
     * Bounded stderr capture: keeps only the last {@link #STDERR_TAIL_BYTES} so a chatty nuclei
     * (it logs every template error at -v) can't grow this without limit, while the final fatal
     * line - always the last thing written - is guaranteed to survive.
     */
    static final class StderrTail {
        private final byte[] ring = new byte[STDERR_TAIL_BYTES];
        private int written = 0;

        void drain(InputStream stderr) throws IOException {
            byte[] buf = new byte[1024];
            int n;
            while ((n = stderr.read(buf)) != -1) {
                for (int i = 0; i < n; i++) {
                    ring[written++ % ring.length] = buf[i];
                }
            }
        }

        /** Only meaningful after the draining thread has been joined - no locking, the join is the happens-before. */
        String text() {
            int len = Math.min(written, ring.length);
            ByteArrayOutputStream out = new ByteArrayOutputStream(len);
            int start = written > ring.length ? written % ring.length : 0;
            for (int i = 0; i < len; i++) {
                out.write(ring[(start + i) % ring.length]);
            }
            return out.toString(StandardCharsets.UTF_8).strip();
        }
    }
}
