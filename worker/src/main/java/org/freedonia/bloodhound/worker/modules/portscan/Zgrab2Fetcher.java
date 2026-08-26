package org.freedonia.bloodhound.worker.modules.portscan;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;

/**
 * Wraps the {@code zgrab2} binary (Apache-2.0/ISC, ZMap project) via
 * ProcessBuilder for Tier 2's service identification - one open port at a
 * time, one target per invocation, target fed over stdin (zgrab2's own
 * input format).
 *
 * <p>There's no scripted-probe-library equivalent to draw on here, and no
 * permissively-licensed drop-in for a large accumulated service/version
 * fingerprint database - deliberately not attempted, since reproducing
 * another scanner's own proprietary signature data would just trade one
 * licensing problem for another. This is an honest, narrower identification
 * pass: a raw banner grab for self-announcing protocols
 * (SSH/FTP/SMTP/POP3/IMAP/...), plus a dedicated HTTP(S) probe for the
 * common web ports to read the Server header - see BannerDecisionLogic for
 * what's inferred from either.
 *
 * <p>Same process-handling pattern as every other subprocess wrapper in this
 * module, plus a concurrent stdin-writer thread (zgrab2 reads its target
 * from stdin) alongside the usual concurrent stderr drain - both needed so
 * neither pipe can fill and deadlock the exchange.
 */
public class Zgrab2Fetcher {

    private static final long HARD_TIMEOUT_SECONDS = 15;

    /**
     * zgrab2 refuses to start without a blocklist file and otherwise looks
     * for one under $HOME/.config/zgrab2/, which doesn't exist in the worker
     * image - see the empty file baked in by the Dockerfile at this exact
     * path. Bloodhound already enforces its own SSRF/private-range guard
     * (SafeAddressValidator) upstream of every scan module, so an empty
     * zgrab2 blocklist isn't giving anything up.
     */
    private static final String BLOCKLIST_FILE = "/etc/zgrab2-blocklist.conf";

    public String bannerJson(String ip, int port) throws ScanModuleException {
        return run(List.of(
                "zgrab2", "banner", "-b", BLOCKLIST_FILE, "-p", String.valueOf(port),
                "--connect-timeout", "4s", "--read-timeout", "2000"), ip);
    }

    public String httpJson(String ip, int port, boolean tls) throws ScanModuleException {
        List<String> command = new ArrayList<>(List.of(
                "zgrab2", "http", "-b", BLOCKLIST_FILE, "-p", String.valueOf(port), "--connect-timeout", "4s"));
        if (tls) {
            command.add("--use-https");
        }
        return run(command, ip);
    }

    private String run(List<String> command, String ip) throws ScanModuleException {
        ProcessBuilder pb = new ProcessBuilder(command);
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

            Thread stdinWriter = new Thread(() -> {
                try (OutputStream stdin = started.getOutputStream()) {
                    stdin.write((ip + "\n").getBytes(StandardCharsets.UTF_8));
                } catch (java.io.IOException ignored) {
                }
            });
            stdinWriter.setDaemon(true);
            stdinWriter.start();

            String output = readAll(process.getInputStream());
            boolean finished = process.waitFor(HARD_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new ScanModuleException(
                        "zgrab2 call against " + ip + " exceeded the hard " + HARD_TIMEOUT_SECONDS + "s timeout");
            }
            return output;
        } catch (java.io.IOException e) {
            throw new ScanModuleException("failed to invoke zgrab2 for " + ip, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ScanModuleException("zgrab2 call against " + ip + " was interrupted", e);
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
