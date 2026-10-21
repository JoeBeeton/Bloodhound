package org.freedonia.bloodhound.worker.ruleit;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * TLS on 443. The server offers SSLv3 through TLS 1.2 and not TLS 1.3, so every scan of a
 * reachable host fires TLS_1_3_NOT_SUPPORTED. SNI selects the bad, soon, or good alias.
 */
public final class TlsServer implements AutoCloseable {

    private final SSLServerSocket server;
    private final ExecutorService pool;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final Thread acceptThread;

    private TlsServer(SSLServerSocket server, LoopbackHttpServer.Router router) {
        this.server = server;
        this.pool = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "bh-rule-tls");
            thread.setDaemon(true);
            return thread;
        });
        this.acceptThread = new Thread(() -> {
            while (running.get()) {
                try {
                    SSLSocket socket = (SSLSocket) server.accept();
                    pool.submit(() -> {
                        try {
                            socket.startHandshake();
                            LoopbackHttpServer.handle(socket, true, router);
                        } catch (Exception e) {
                            try {
                                socket.close();
                            } catch (Exception ignored) {
                                // already closed
                            }
                        }
                    });
                } catch (Exception e) {
                    return;
                }
            }
        }, "bh-rule-tls-accept");
        this.acceptThread.setDaemon(true);
        this.acceptThread.start();
    }

    public static TlsServer start(LoopbackHttpServer.Router router) throws Exception {
        String dir = System.getProperty("bloodhound.rule.fixture.dir");
        if (dir == null) {
            throw new IllegalStateException("bloodhound.rule.fixture.dir is not set");
        }
        Path keystorePath = Path.of(dir, "server.p12");
        if (!Files.isRegularFile(keystorePath)) {
            throw new IllegalStateException("missing " + keystorePath);
        }
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(keystorePath)) {
            keystore.load(in, CertMaterial.PASSWORD);
        }
        KeyManagerFactory factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keystore, CertMaterial.PASSWORD);
        X509ExtendedKeyManager delegate = null;
        for (KeyManager manager : factory.getKeyManagers()) {
            if (manager instanceof X509ExtendedKeyManager extended) {
                delegate = extended;
                break;
            }
        }
        if (delegate == null) {
            throw new IllegalStateException("no X509ExtendedKeyManager");
        }
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(new KeyManager[] {new SniKeyManager(delegate)}, null, null);
        SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(443, 64, InetAddress.getByAddress(new byte[] {127, 0, 0, 1}));
        server.setReuseAddress(true);
        List<String> enabled = new ArrayList<>();
        for (String protocol : server.getSupportedProtocols()) {
            if ("SSLv3".equals(protocol) || "TLSv1".equals(protocol) || "TLSv1.1".equals(protocol)
                    || "TLSv1.2".equals(protocol)) {
                enabled.add(protocol);
            }
        }
        server.setEnabledProtocols(enabled.toArray(String[]::new));
        server.setWantClientAuth(false);
        return new TlsServer(server, router);
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

    private static final class SniKeyManager extends X509ExtendedKeyManager {
        private final X509ExtendedKeyManager delegate;

        private SniKeyManager(X509ExtendedKeyManager delegate) {
            this.delegate = delegate;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return aliasFor(sniHost(socket));
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, javax.net.ssl.SSLEngine engine) {
            String host = null;
            if (engine.getHandshakeSession() instanceof ExtendedSSLSession session) {
                host = firstHost(session.getRequestedServerNames());
            }
            return aliasFor(host);
        }

        private static String aliasFor(String host) {
            if (FixtureHosts.TLS_BAD.equals(host)) {
                return "bad";
            }
            if (FixtureHosts.TLS_SOON.equals(host)) {
                return "soon";
            }
            return "good";
        }

        private static String sniHost(Socket socket) {
            if (!(socket instanceof SSLSocket ssl)) {
                return null;
            }
            if (!(ssl.getHandshakeSession() instanceof ExtendedSSLSession session)) {
                return null;
            }
            return firstHost(session.getRequestedServerNames());
        }

        private static String firstHost(List<SNIServerName> names) {
            for (SNIServerName name : names) {
                if (name instanceof SNIHostName host) {
                    return host.getAsciiName().toLowerCase(Locale.ROOT);
                }
            }
            return null;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return delegate.getClientAliases(keyType, issuers);
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return delegate.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return new String[] {"good", "bad", "soon"};
        }

        @Override
        public java.security.cert.X509Certificate[] getCertificateChain(String alias) {
            return delegate.getCertificateChain(alias);
        }

        @Override
        public java.security.PrivateKey getPrivateKey(String alias) {
            return delegate.getPrivateKey(alias);
        }
    }
}
