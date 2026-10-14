package org.freedonia.bloodhound.worker.modules.portscan;

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.freedonia.bloodhound.common.net.SafeHttpGet;
import org.freedonia.bloodhound.common.net.ScanUserAgent;
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
     * A security review found this had two bugs, the same class already fixed elsewhere this
     * session: readAll() had no size cap at all (unbounded, the exact shape SafeHttpGet was
     * introduced to fix for HTTP responses), AND it ran BEFORE process.waitFor(HARD_TIMEOUT_SECONDS)
     * - meaning a zgrab2 child process that hangs without closing stdout (a target trickling a
     * slow-but-nonzero response, the same class of attack FtpAnonymousChecker's own fix already
     * covers for raw sockets) blocked forever reading stdout, and the "hard timeout" below never
     * even got a chance to run, since the blocking read came first. Fixed with the same watchdog
     * pattern FtpAnonymousChecker uses: a shared daemon-threaded ScheduledExecutorService
     * force-destroys the process after the deadline - unlike Thread.interrupt() (which has no
     * effect on a thread blocked in a classic blocking read), destroying the process closes its
     * stdout pipe from another thread, which does reliably unblock the read.
     */
    private static final int MAX_OUTPUT_BYTES = 1_000_000;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "zgrab2-watchdog");
        thread.setDaemon(true);
        return thread;
    });

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

    /**
     * A full SSH transport-layer handshake, reporting the server's own offered KEX/host-key/
     * cipher/MAC algorithm lists (not just what a client happened to pick) - the same "what will
     * this server accept if offered" signal WeakCipherProbe's own javadoc describes for TLS,
     * applied to SSH. Verified live against a real server (github.com:22) before building the
     * parser: {@code data.ssh.result.server_key_exchange} carries {@code kex_algorithms}/
     * {@code host_key_algorithms}/{@code client_to_server_ciphers}/{@code server_to_client_ciphers}/
     * {@code client_to_server_macs}/{@code server_to_client_macs}, each a plain array of algorithm
     * name strings.
     */
    public String sshJson(String ip, int port) throws ScanModuleException {
        return run(
                List.of("zgrab2", "ssh", "-b", BLOCKLIST_FILE, "-p", String.valueOf(port), "--connect-timeout", "4s"), ip);
    }

    public String httpJson(String ip, int port, boolean tls) throws ScanModuleException {
        // --user-agent: the http submodule is the only zgrab2 mode that speaks HTTP at all
        // (banner grabs below are raw TCP for self-announcing protocols with no header
        // mechanism) - identifies this probe the same way every other outbound HTTP request
        // this platform makes does, see ScanUserAgent.
        List<String> command = new ArrayList<>(List.of(
                "zgrab2", "http", "-b", BLOCKLIST_FILE, "-p", String.valueOf(port), "--connect-timeout", "4s",
                "--user-agent", ScanUserAgent.VALUE));
        if (tls) {
            command.add("--use-https");
        }
        return run(command, ip);
    }

    /**
     * A TLS handshake offering exactly {@code cipherSuiteHex} (IANA codes, "0x000a" form) and
     * nothing newer than TLS 1.2 - the way to ask "would this server accept a weak suite?", which
     * the JDK's own client can't do (it refuses to offer RC4/3DES/DES/NULL/anon at all). Input is
     * zgrab2's "IP,DOMAIN" form: connect to the already-validated address, SNI from the name.
     */
    public String tlsJson(String ip, String sniHostname, int port, List<String> cipherSuiteHex)
            throws ScanModuleException {
        return run(
                List.of(
                        "zgrab2", "tls", "-b", BLOCKLIST_FILE, "-p", String.valueOf(port),
                        "--max-version", "771", // TLS 1.2 - otherwise zgrab2 adds the 1.3 suites regardless of the list
                        "--cipher-suite", String.join(",", cipherSuiteHex)),
                ip + "," + sniHostname);
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
            // Reap only - by this point the process has either finished naturally (readCappedUtf8
            // returned via real EOF) or been force-destroyed by the watchdog above, so this should
            // return near-instantly either way; the outer finally block below still catches the
            // rare case where it somehow hasn't.
            process.waitFor(2, TimeUnit.SECONDS);
            if (timedOut.get()) {
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
}
