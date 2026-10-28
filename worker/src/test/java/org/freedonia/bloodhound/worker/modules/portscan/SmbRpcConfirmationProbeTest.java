package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import org.junit.jupiter.api.Test;

/**
 * Real loopback TCP servers, not mocks - the point of this probe is genuinely about what bytes
 * come back over the wire, same reasoning as FtpAnonymousCheckerTest's own doc.
 */
class SmbRpcConfirmationProbeTest {

    private interface FakeServerBehavior {
        void run(Socket client) throws Exception;
    }

    private static Thread startFakeServer(ServerSocket serverSocket, FakeServerBehavior behavior) {
        Thread thread = new Thread(() -> {
            try (Socket client = serverSocket.accept()) {
                behavior.run(client);
            } catch (Exception ignored) {
                // Test is over - nothing left to do.
            }
        });
        thread.setDaemon(true);
        thread.start();
        return thread;
    }

    private static InetAddress loopback() throws IOException {
        return InetAddress.getByName("127.0.0.1");
    }

    /** Reads whatever the probe sent, just so a behavior can inspect it if it needs to - unused by most tests here. */
    private static byte[] drainRequest(Socket client) throws IOException {
        InputStream in = client.getInputStream();
        byte[] buffer = new byte[512];
        int read = in.read(buffer);
        return read < 0 ? new byte[0] : java.util.Arrays.copyOf(buffer, read);
    }

    @Test
    void smb2Server_repliesWithSmb2Magic_confirmed() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                OutputStream out = client.getOutputStream();
                out.write(new byte[] {(byte) 0xFE, 'S', 'M', 'B', 0, 0, 0, 0});
                out.flush();
            });

            assertThat(SmbRpcConfirmationProbe.confirmSmb(loopback(), serverSocket.getLocalPort())).isTrue();
        }
    }

    @Test
    void legacySmb1Server_repliesWithSmb1Magic_stillConfirmed() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                OutputStream out = client.getOutputStream();
                out.write(new byte[] {(byte) 0xFF, 'S', 'M', 'B', 0, 0, 0, 0});
                out.flush();
            });

            assertThat(SmbRpcConfirmationProbe.confirmSmb(loopback(), serverSocket.getLocalPort())).isTrue();
        }
    }

    @Test
    void nonSmbServer_repliesWithUnrelatedBytes_notConfirmed() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                OutputStream out = client.getOutputStream();
                out.write("HTTP/1.1 400 Bad Request\r\n\r\n".getBytes());
                out.flush();
            });

            assertThat(SmbRpcConfirmationProbe.confirmSmb(loopback(), serverSocket.getLocalPort())).isFalse();
        }
    }

    @Test
    void serverAcceptsThenNeverReplies_notConfirmed() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                Thread.sleep(10_000); // longer than the probe's own read timeout
            });

            assertThat(SmbRpcConfirmationProbe.confirmSmb(loopback(), serverSocket.getLocalPort())).isFalse();
        }
    }

    @Test
    void portNeverAcceptsAConnection_notConfirmed() throws Exception {
        int unusedPort;
        try (ServerSocket probe = new ServerSocket(0)) {
            unusedPort = probe.getLocalPort();
        }
        // The ServerSocket above is now closed, so this port refuses the connection outright.
        assertThat(SmbRpcConfirmationProbe.confirmSmb(loopback(), unusedPort)).isFalse();
    }

    @Test
    void rpcServer_repliesWithBindAck_confirmed() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                OutputStream out = client.getOutputStream();
                out.write(new byte[] {5, 0, 12, 3}); // rpc_vers=5, PTYPE=12 (bind_ack)
                out.flush();
            });

            assertThat(SmbRpcConfirmationProbe.confirmRpcBind(loopback(), serverSocket.getLocalPort())).isTrue();
        }
    }

    @Test
    void rpcServer_repliesWithBindNak_stillConfirmed() throws Exception {
        // A bind_nak still proves a real DCE/RPC implementation parsed our PDU and replied
        // in-protocol, even though it rejected this exact binding - see the probe's own doc.
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                OutputStream out = client.getOutputStream();
                out.write(new byte[] {5, 0, 13, 3}); // rpc_vers=5, PTYPE=13 (bind_nak)
                out.flush();
            });

            assertThat(SmbRpcConfirmationProbe.confirmRpcBind(loopback(), serverSocket.getLocalPort())).isTrue();
        }
    }

    @Test
    void rpcServer_repliesWithUnrelatedBytes_notConfirmed() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                OutputStream out = client.getOutputStream();
                out.write(new byte[] {(byte) 0xFE, 'S', 'M', 'B'}); // an SMB reply, not RPC
                out.flush();
            });

            assertThat(SmbRpcConfirmationProbe.confirmRpcBind(loopback(), serverSocket.getLocalPort())).isFalse();
        }
    }

    @Test
    void confirm_dispatchesToSmbProbeOnlyForLiteralPort445() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(0)) {
            startFakeServer(serverSocket, client -> {
                drainRequest(client);
                OutputStream out = client.getOutputStream();
                out.write(new byte[] {(byte) 0xFE, 'S', 'M', 'B'});
                out.flush();
            });

            // Not port 445, so confirm() must not even try - regardless of what the server replies.
            assertThat(SmbRpcConfirmationProbe.confirm(loopback(), serverSocket.getLocalPort())).isFalse();
        }
    }
}
