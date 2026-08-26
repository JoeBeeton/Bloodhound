package org.freedonia.bloodhound.worker.modules.portscan;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.concurrent.TimeUnit;
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
            String output = readAll(process.getInputStream());
            boolean finished = process.waitFor(HARD_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
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

    private String readAll(InputStream in) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        in.transferTo(out);
        return out.toString(java.nio.charset.StandardCharsets.UTF_8);
    }
}
