package org.freedonia.bloodhound.worker.modules.subdomain;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;
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

            String stdout = readAll(process.getInputStream());
            boolean finished = process.waitFor(HARD_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
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

    private String readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        in.transferTo(out);
        return out.toString(StandardCharsets.UTF_8);
    }
}
