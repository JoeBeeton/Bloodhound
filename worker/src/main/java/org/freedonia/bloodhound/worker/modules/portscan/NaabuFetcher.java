package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Wraps the {@code naabu} binary (MIT-licensed, ProjectDiscovery - installed
 * in the worker image alongside subfinder) via ProcessBuilder for Tier 2's
 * full 1-65535 port-range discovery.
 *
 * <p>Given a resolved IP (never a hostname - see DeepPortScanModule, which
 * resolves once and reuses the address for both this and Zgrab2Fetcher,
 * rather than letting naabu do its own separate DNS resolution). Same
 * process-handling pattern as every other subprocess wrapper in this module
 * (concurrent stderr drain to avoid pipe-buffer deadlock, hard wall-clock
 * timeout with forced destruction).
 */
public class NaabuFetcher {

    private static final long HARD_TIMEOUT_SECONDS = 300; // 5 minutes - full 1-65535 range

    /**
     * A security review found this had the same two bugs already fixed in Zgrab2Fetcher/
     * NucleiFetcher this session: readAll() had no size cap at all, AND it ran BEFORE
     * process.waitFor(HARD_TIMEOUT_SECONDS) - a naabu child process hung without closing stdout
     * blocked this forever, and the "hard timeout" never got a chance to run. Same watchdog fix:
     * a shared daemon ScheduledExecutorService force-destroys the process after the deadline,
     * which (unlike Thread.interrupt()) reliably unblocks a thread stuck reading its stdout pipe.
     * A full 1-65535 port sweep's JSON-lines output (one line per open port) is naturally larger
     * than a single-probe tool's - generous relative to that.
     */
    private static final int MAX_OUTPUT_BYTES = 5_000_000;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "naabu-watchdog");
        thread.setDaemon(true);
        return thread;
    });

    public String fetchJsonLines(String ip) throws ScanModuleException {
        ProcessBuilder pb = new ProcessBuilder(
                "naabu", "-host", ip, "-p", "1-65535", "-json", "-silent",
                "-timeout", "1500", "-retries", "1", "-rate", "2000");
        Process process = null;
        try {
            final Process started = pb.start();
            process = started;
            Thread stderrDrain = new Thread(() -> {
                try {
                    started.getErrorStream().transferTo(java.io.OutputStream.nullOutputStream());
                } catch (java.io.IOException ignored) {
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
            // Reap only - by this point the process has either finished naturally or been
            // force-destroyed by the watchdog above, so this should return near-instantly.
            process.waitFor(2, TimeUnit.SECONDS);
            if (timedOut.get()) {
                throw new ScanModuleException(
                        "naabu scan of " + ip + " exceeded the hard " + HARD_TIMEOUT_SECONDS + "s timeout");
            }
            return output;
        } catch (java.io.IOException e) {
            throw new ScanModuleException("failed to invoke naabu for " + ip, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanModuleException("naabu scan of " + ip + " was interrupted", e);
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
