package org.freedonia.bloodhound.worker.modules.subdomain;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shared process-invocation plumbing for CLI-backed passive subdomain
 * sources (subfinder today; amass or others could follow the same shape).
 * Mirrors the hard-timeout / concurrent-stderr-drain pattern this codebase's
 * other subprocess-invoking modules use, to avoid the exact pipe-buffer
 * deadlock class those had to find and fix. Unlike CrtShSource - which treats a failed fetch as
 * a hard module failure - a missing/failing external binary here is treated
 * as "this source found nothing": SubdomainEnumModule aggregates several
 * sources, and one flaky/absent CLI tool shouldn't fail the whole scan when
 * other sources can still contribute.
 */
public abstract class ExternalCliSubdomainSource implements SubdomainSource {

    private static final Logger log = LoggerFactory.getLogger(ExternalCliSubdomainSource.class);
    private static final long HARD_TIMEOUT_SECONDS = 75;

    /**
     * A security review found this had the same two bugs already fixed elsewhere this session
     * (Zgrab2Fetcher, NucleiFetcher, NaabuFetcher): readAll() had no size cap at all, AND it ran
     * BEFORE process.waitFor(HARD_TIMEOUT_SECONDS) - a subfinder (or future CLI source) child
     * process hung without closing stdout blocked this forever, and the "hard timeout" never got
     * a chance to run. Same watchdog fix: a shared daemon ScheduledExecutorService force-destroys
     * the process after the deadline, which (unlike Thread.interrupt()) reliably unblocks a
     * thread stuck reading its stdout pipe.
     */
    private static final int MAX_OUTPUT_BYTES = 5_000_000;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "external-cli-subdomain-watchdog");
        thread.setDaemon(true);
        return thread;
    });

    protected abstract List<String> command(String rootDomain);

    protected abstract List<String> parseOutput(String stdout);

    @Override
    public List<String> discover(String rootDomain) {
        List<String> command = command(rootDomain);
        Process process = null;
        try {
            process = new ProcessBuilder(command).start();
            final Process started = process;
            Thread stderrDrain = new Thread(() -> {
                try {
                    started.getErrorStream().transferTo(OutputStream.nullOutputStream());
                } catch (IOException ignored) {
                    // nothing in stderr is needed for parsing; discard.
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
            String stdout;
            try {
                stdout = SafeHttpGet.readCappedUtf8(process.getInputStream(), MAX_OUTPUT_BYTES);
            } finally {
                deadline.cancel(false);
            }
            // Reap only - by this point the process has either finished naturally or been
            // force-destroyed by the watchdog above, so this should return near-instantly; the
            // explicit reaped check (not just timedOut) guards the exitValue() call below, which
            // throws IllegalThreadStateException on a still-alive process.
            boolean reaped = process.waitFor(2, TimeUnit.SECONDS);
            if (timedOut.get() || !reaped) {
                log.warn("{} timed out after {}s for {}", sourceName(), HARD_TIMEOUT_SECONDS, rootDomain);
                return List.of();
            }
            if (process.exitValue() != 0 && stdout.isBlank()) {
                log.warn("{} exited {} with no output for {}", sourceName(), process.exitValue(), rootDomain);
                return List.of();
            }
            return parseOutput(stdout);
        } catch (IOException e) {
            // Binary missing/not executable in this image, or failed to start.
            log.warn("{} unavailable ({}); continuing with other sources", sourceName(), e.getMessage());
            return List.of();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("{} interrupted for {}", sourceName(), rootDomain);
            return List.of();
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }
}
