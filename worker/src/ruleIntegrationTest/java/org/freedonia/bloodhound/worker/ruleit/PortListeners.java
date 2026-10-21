package org.freedonia.bloodhound.worker.ruleit;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Alt-port HTTP, Redis, and TCP sinks. Open only for the test that needs them so port scans do not see them. */
public final class PortListeners {

    private static final List<LoopbackHttpServer> HTTP = new ArrayList<>();
    private static RedisInfoServer redis;

    private PortListeners() {}

    public static void startExposurePorts() throws Exception {
        stopExposurePorts();
        HTTP.add(LoopbackHttpServer.start(2375, (tls, request) -> HttpResponses.bytes(200, "application/json", "{\"ApiVersion\":\"1.41\"}".getBytes(StandardCharsets.UTF_8))));
        HTTP.add(LoopbackHttpServer.start(9200, (tls, request) -> HttpResponses.text(200, "application/json", "{\"cluster_name\":\"bh\"}")));
        HTTP.add(LoopbackHttpServer.start(8500, (tls, request) -> HttpResponses.text(200, "application/json", "\"127.0.0.1:8300\"")));
        HTTP.add(LoopbackHttpServer.start(3000, (tls, request) -> HttpResponses.text(200, "application/json", "{\"database\":\"ok\",\"version\":\"9.0.0\"}")));
        HTTP.add(LoopbackHttpServer.start(8081, (tls, request) -> HttpResponses.text(200, "text/html", "<html>Mongo Express</html>")));
        HTTP.add(LoopbackHttpServer.start(8080, (tls, request) -> HttpResponses.text(200, "application/json", "{\"backends\":{},\"frontends\":{}}")));
        redis = RedisInfoServer.start();
    }

    public static void stopExposurePorts() {
        for (LoopbackHttpServer server : HTTP) {
            server.close();
        }
        HTTP.clear();
        if (redis != null) {
            redis.close();
            redis = null;
        }
    }

    /** Accepts and closes. Enough for a TCP connect scan. */
    public static final class PortSink implements AutoCloseable {
        private final List<ServerSocket> sockets = new ArrayList<>();
        private final ExecutorService pool = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "bh-rule-sink");
            thread.setDaemon(true);
            return thread;
        });

        public static PortSink open(int... ports) throws Exception {
            PortSink sink = new PortSink();
            InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
            for (int port : ports) {
                ServerSocket server = new ServerSocket();
                server.setReuseAddress(true);
                server.bind(new InetSocketAddress(loopback, port));
                sink.sockets.add(server);
                sink.pool.submit(() -> {
                    while (!server.isClosed()) {
                        try (Socket socket = server.accept()) {
                            socket.close();
                        } catch (Exception e) {
                            return;
                        }
                    }
                });
            }
            return sink;
        }

        @Override
        public void close() {
            for (ServerSocket server : sockets) {
                try {
                    server.close();
                } catch (Exception ignored) {
                    // already closed
                }
            }
            pool.shutdownNow();
        }
    }

    private static final class RedisInfoServer implements AutoCloseable {
        private final ServerSocket server;
        private final ExecutorService pool;
        private final Thread acceptThread;

        private RedisInfoServer(ServerSocket server) {
            this.server = server;
            this.pool = Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "bh-rule-redis");
                thread.setDaemon(true);
                return thread;
            });
            this.acceptThread = new Thread(() -> {
                while (!server.isClosed()) {
                    try {
                        Socket socket = server.accept();
                        pool.submit(() -> reply(socket));
                    } catch (Exception e) {
                        return;
                    }
                }
            }, "bh-rule-redis-accept");
            this.acceptThread.setDaemon(true);
            this.acceptThread.start();
        }

        static RedisInfoServer start() throws Exception {
            ServerSocket server = new ServerSocket();
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), 6379));
            return new RedisInfoServer(server);
        }

        private static void reply(Socket socket) {
            try (socket) {
                socket.setSoTimeout(3_000);
                InputStream in = socket.getInputStream();
                byte[] buf = new byte[64];
                in.read(buf);
                String payload = "# Server\r\nredis_version:6.2.0\r\n";
                String response = "$" + payload.length() + "\r\n" + payload;
                OutputStream out = socket.getOutputStream();
                out.write(response.getBytes(StandardCharsets.US_ASCII));
                out.flush();
            } catch (Exception ignored) {
                // probe gave up
            }
        }

        @Override
        public void close() {
            try {
                server.close();
            } catch (Exception ignored) {
                // already closed
            }
            pool.shutdownNow();
        }
    }
}
