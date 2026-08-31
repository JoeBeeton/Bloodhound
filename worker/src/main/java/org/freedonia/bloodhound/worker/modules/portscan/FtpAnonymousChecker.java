package org.freedonia.bloodhound.worker.modules.portscan;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * A direct, minimal FTP anonymous-login probe - RFC 959's USER/PASS
 * exchange - standing in for the anonymous-login script a prior revision's
 * CLI-based scanner used to run. Only ever called by DeepPortScanModule
 * against a host with port 21 already confirmed open by naabu.
 */
final class FtpAnonymousChecker {

    private static final int TIMEOUT_MS = 5000;

    /**
     * A security review found {@code setSoTimeout} alone doesn't bound the OVERALL exchange - it
     * resets on every individual {@code readLine()} call, so a malicious server on a scanned
     * host (attacker-controlled by definition: this probes whatever a target's own open port 21
     * answers with) trickling less than a full line every {@code TIMEOUT_MS} could keep every
     * individual read from ever timing out while the exchange as a whole runs indefinitely.
     * Worse, the caller (DeepPortScanModule#identifyServices) wraps this in a
     * {@code Future.get(timeout)} + {@code shutdownNow()}, which relies on {@code
     * Thread.interrupt()} to actually stop a still-running task - but interrupting a thread
     * blocked in a classic (non-NIO) blocking socket read does nothing at all, so that guard
     * silently fails to free either the thread or the socket. {@link #WATCHDOG} enforces a real
     * overall deadline by force-closing the socket instead, which - unlike interrupt() - reliably
     * unblocks a thread stuck in a blocking read (it throws immediately). 3x the per-read timeout,
     * not the same value, so a handful of legitimately slow-but-real round trips (banner, USER,
     * PASS) each individually still within {@link #TIMEOUT_MS} don't get force-closed as if they
     * were the attack this exists to bound.
     */
    private static final int OVERALL_DEADLINE_MS = TIMEOUT_MS * 3;

    private static final int FTP_PORT = 21;

    private static final ScheduledExecutorService WATCHDOG = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "ftp-anon-watchdog");
        thread.setDaemon(true);
        return thread;
    });

    private FtpAnonymousChecker() {}

    /** Returns the server's success response line if anonymous login worked, otherwise null. */
    static String checkAnonymousLogin(InetAddress address) {
        return checkAnonymousLogin(address, FTP_PORT);
    }

    /** Port parameterized separately so tests can point this at a real loopback server on an ephemeral port rather than the real FTP_PORT (21). */
    static String checkAnonymousLogin(InetAddress address, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address, port), TIMEOUT_MS);
            socket.setSoTimeout(TIMEOUT_MS);
            ScheduledFuture<?> deadline =
                    WATCHDOG.schedule(() -> closeQuietly(socket), OVERALL_DEADLINE_MS, TimeUnit.MILLISECONDS);
            try {
                return exchange(socket);
            } finally {
                // No-op once the exchange already finished (the common case) - only ever actually
                // fires the close for an exchange still running past the deadline.
                deadline.cancel(false);
            }
        } catch (Exception e) {
            return null;
        }
    }

    private static String exchange(Socket socket) throws IOException {
        BufferedReader in =
                new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
        PrintWriter out =
                new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.US_ASCII), true);

        in.readLine(); // 220 banner - not needed, just clears it off the wire

        out.print("USER anonymous\r\n");
        out.flush();
        String userResponse = in.readLine();
        if (userResponse == null || !userResponse.startsWith("331")) {
            return null; // server didn't even prompt for a password the normal way
        }

        out.print("PASS anonymous@example.com\r\n");
        out.flush();
        String passResponse = in.readLine();
        if (passResponse != null && passResponse.startsWith("230")) {
            return "Anonymous FTP login succeeded: " + passResponse;
        }
        return null;
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // The whole point of closing here is to unblock a stuck read from another thread -
            // any failure closing an already-broken socket is not this watchdog's problem.
        }
    }
}
