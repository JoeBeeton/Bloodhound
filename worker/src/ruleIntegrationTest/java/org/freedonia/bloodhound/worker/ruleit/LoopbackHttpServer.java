package org.freedonia.bloodhound.worker.ruleit;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/** HTTP/1.1, one request per connection. Connection: close so the JDK client does not reuse a half-closed socket. */
public final class LoopbackHttpServer implements AutoCloseable {

    @FunctionalInterface
    public interface Router {
        HttpResponses.Response route(boolean tls, HttpResponses.Request request);
    }

    private final ServerSocket server;
    private final ExecutorService pool;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Thread acceptThread;

    private LoopbackHttpServer(ServerSocket server, Router router, boolean tls) {
        this.server = server;
        this.pool = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "bh-rule-http-" + server.getLocalPort());
            thread.setDaemon(true);
            return thread;
        });
        this.acceptThread = new Thread(() -> acceptLoop(router, tls), "bh-rule-http-accept-" + server.getLocalPort());
        this.acceptThread.setDaemon(true);
        this.acceptThread.start();
    }

    public static LoopbackHttpServer start(int port, Router router) throws Exception {
        ServerSocket server = new ServerSocket();
        server.setReuseAddress(true);
        server.bind(new InetSocketAddress(InetAddress.getByAddress(new byte[] {127, 0, 0, 1}), port), 64);
        return new LoopbackHttpServer(server, router, false);
    }

    private void acceptLoop(Router router, boolean tls) {
        while (running.get()) {
            try {
                Socket socket = server.accept();
                pool.submit(() -> handle(socket, tls, router));
            } catch (Exception e) {
                return;
            }
        }
    }

    static void handle(Socket socket, boolean tls, Router router) {
        try (socket) {
            socket.setSoTimeout(8_000);
            InputStream in = socket.getInputStream();
            ByteArrayOutputStream head = new ByteArrayOutputStream();
            int prev3 = 0;
            int prev2 = 0;
            int prev = 0;
            while (true) {
                int b = in.read();
                if (b < 0) {
                    return;
                }
                head.write(b);
                if (head.size() > 65_536) {
                    return;
                }
                if (prev3 == '\r' && prev2 == '\n' && prev == '\r' && b == '\n') {
                    break;
                }
                prev3 = prev2;
                prev2 = prev;
                prev = b;
            }
            String raw = head.toString(StandardCharsets.ISO_8859_1);
            String[] lines = raw.split("\r\n", -1);
            String[] requestLine = lines[0].split(" ", 3);
            String method = requestLine.length > 0 ? requestLine[0] : "GET";
            String path = requestLine.length > 1 ? requestLine[1] : "/";
            int query = path.indexOf('?');
            if (query >= 0) {
                path = path.substring(0, query);
            }
            Map<String, List<String>> headers = new LinkedHashMap<>();
            for (int i = 1; i < lines.length; i++) {
                int colon = lines[i].indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String name = lines[i].substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = lines[i].substring(colon + 1).trim();
                headers.computeIfAbsent(name, key -> new ArrayList<>()).add(value);
            }
            int contentLength = 0;
            if (headers.containsKey("content-length")) {
                try {
                    contentLength = Integer.parseInt(headers.get("content-length").get(0));
                } catch (NumberFormatException ignored) {
                    contentLength = 0;
                }
            }
            if (contentLength > 0 && contentLength < 1_000_000) {
                in.readNBytes(contentLength);
            }
            String host = headers.getOrDefault("host", List.of("")).isEmpty()
                    ? ""
                    : headers.get("host").get(0);
            int colon = host.lastIndexOf(':');
            if (colon > 0 && host.substring(colon + 1).chars().allMatch(Character::isDigit)) {
                host = host.substring(0, colon);
            }
            host = host.toLowerCase(Locale.ROOT);
            HttpResponses.Response response =
                    router.route(tls, new HttpResponses.Request(method, path, host, headers, raw));
            write(socket.getOutputStream(), response);
        } catch (Exception ignored) {
            // The client closed, or the handshake failed. One connection is not the suite.
        }
    }

    private static void write(OutputStream out, HttpResponses.Response response) throws Exception {
        byte[] body = response.body() == null ? new byte[0] : response.body();
        StringBuilder head = new StringBuilder();
        head.append("HTTP/1.1 ").append(response.status()).append(' ').append(reason(response.status())).append("\r\n");
        if (response.contentType() != null) {
            head.append("Content-Type: ").append(response.contentType()).append("\r\n");
        }
        head.append("Content-Length: ").append(body.length).append("\r\n");
        head.append("Connection: close\r\n");
        for (Map.Entry<String, List<String>> header : response.headers().entrySet()) {
            for (String value : header.getValue()) {
                head.append(header.getKey()).append(": ").append(value).append("\r\n");
            }
        }
        head.append("\r\n");
        out.write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }

    private static String reason(int status) {
        return switch (status) {
            case 200 -> "OK";
            case 301 -> "Moved Permanently";
            case 404 -> "Not Found";
            case 405 -> "Method Not Allowed";
            default -> "OK";
        };
    }

    @Override
    public void close() {
        running.set(false);
        try {
            server.close();
        } catch (Exception ignored) {
            // already closed
        }
        pool.shutdownNow();
    }
}
