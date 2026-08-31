package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Real loopback TCP servers, not mocks - the bug this exists to cover (a malicious server
 * trickling bytes to keep a blocking socket read from ever timing out) is genuinely about socket
 * I/O semantics, not something a mock can reproduce.
 */
class FtpAnonymousCheckerTest {

    private interface FakeServerBehavior {
        void run(Socket client) throws Exception;
    }

    /** Runs a one-shot server on an ephemeral loopback port, handling exactly one connection with the given behavior. */
    private static Thread startFakeServer(ServerSocket serverSocket, FakeServerBehavior behavior) {
        Thread thread = new Thread(() -> {
            try (Socket client = serverSocket.accept()) {
                behavior.run(client);
            } catch (Exception ignored) {
                // Test is over (checkAnonymousLogin's socket was closed, e.g. by the watchdog) -
                // nothing left to do.
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static void writeLine(OutputStream out, String line) throws IOException {
        out.write((line + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
    }

    @Test
    void wellBehavedServer_acceptingAnonymousLogin_returnsTheSuccessLine() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                OutputStream out = client.getOutputStream();
                writeLine(out, "220 Welcome");
                writeLine(out, "331 Please specify the password");
                writeLine(out, "230 Login successful");
            });

            String result = FtpAnonymousChecker.checkAnonymousLogin(loopback(), serverSocket.getLocalPort());

            assertThat(result).contains("230 Login successful");
        }
    }

    @Test
    void serverRefusingAnonymousLogin_returnsNull() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                OutputStream out = client.getOutputStream();
                writeLine(out, "220 Welcome");
                writeLine(out, "530 Login incorrect");
            });

            String result = FtpAnonymousChecker.checkAnonymousLogin(loopback(), serverSocket.getLocalPort());

            assertThat(result).isNull();
        }
    }

    @Test
    void serverTricklingBytesForever_neverCompletesALine_stillReturnsWithinTheOverallDeadline() throws Exception {
        // The actual bug this fix covers: setSoTimeout resets on every individual read, so a
        // server sending less than one full line per window (but never actually going silent)
        // never trips the per-read timeout on its own - only the watchdog's real overall deadline
        // (force-closing the socket) can end this. Before the fix, this test would hang until the
        // JVM/CI process itself was killed.
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                OutputStream out = client.getOutputStream();
                // One byte every 2s, well under the 5s per-read SoTimeout, indefinitely - never a
                // newline, so readLine() never returns on its own.
                while (!client.isClosed()) {
                    out.write('x');
                    out.flush();
                    Thread.sleep(2000);
                }
            });

            long start = System.currentTimeMillis();
            String result = FtpAnonymousChecker.checkAnonymousLogin(loopback(), serverSocket.getLocalPort());
            long elapsedMs = System.currentTimeMillis() - start;

            assertThat(result).isNull();
            // Bounded well below "hangs forever" - generous slack above the watchdog's own
            // deadline for scheduling/CI jitter, but nowhere near unbounded.
            assertThat(elapsedMs).isLessThan(25_000);
        }
    }

    private static InetAddress loopback() throws IOException {
        return InetAddress.getByName("127.0.0.1");
    }
}
