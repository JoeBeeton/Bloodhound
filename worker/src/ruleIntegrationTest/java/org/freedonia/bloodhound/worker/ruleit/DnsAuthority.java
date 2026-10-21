package org.freedonia.bloodhound.worker.ruleit;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Message;
import org.xbill.DNS.NSRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * Authoritative DNS on 1.1.1.1:53, TCP and UDP. Every query is answered (records, NODATA, NXDOMAIN,
 * or REFUSED) so DnsPostureModule does not burn dnsjava's timeout and then fall through.
 */
public final class DnsAuthority implements AutoCloseable {

    private static final List<String> ZONES = List.of(
            FixtureHosts.DNS_ABSENT, FixtureHosts.DNS_BADMAIL, FixtureHosts.DNS_AXFR, FixtureHosts.DNS_LAME);
    private static final Set<String> FIXTURE_HOSTS = Set.copyOf(FixtureHosts.SCANNED);
    private static final long TTL = 300;
    private static final String DKIM_TXT = dkimTxt();

    private static final InetAddress LOOPBACK = address(127, 0, 0, 1);
    private static final InetAddress NS_IP = address(1, 1, 1, 1);
    private static final InetAddress BRAND_IP = address(203, 0, 113, 10);
    private static final InetAddress MAIL_IP = address(203, 0, 113, 50);
    private static final InetAddress WILD_IP = address(203, 0, 113, 9);

    private final DatagramSocket udp;
    private final ServerSocket tcp;
    private final AtomicBoolean running = new AtomicBoolean(true);
    private final ExecutorService tcpPool;
    private final Thread udpThread;
    private final Thread tcpThread;

    private DnsAuthority(DatagramSocket udp, ServerSocket tcp) {
        this.udp = udp;
        this.tcp = tcp;
        this.tcpPool = Executors.newCachedThreadPool(runnable -> {
            Thread thread = new Thread(runnable, "bh-rule-dns-tcp");
            thread.setDaemon(true);
            return thread;
        });
        this.udpThread = new Thread(this::serveUdp, "bh-rule-dns-udp");
        this.udpThread.setDaemon(true);
        this.tcpThread = new Thread(this::serveTcp, "bh-rule-dns-tcp-accept");
        this.tcpThread.setDaemon(true);
        this.udpThread.start();
        this.tcpThread.start();
    }

    public static DnsAuthority start() throws Exception {
        InetAddress bind = NS_IP;
        DatagramSocket udp = new DatagramSocket(53, bind);
        ServerSocket tcp = new ServerSocket(53, 64, bind);
        tcp.setReuseAddress(true);
        return new DnsAuthority(udp, tcp);
    }

    private void serveUdp() {
        while (running.get()) {
            try {
                byte[] buffer = new byte[4096];
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                udp.receive(packet);
                byte[] query = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), packet.getOffset(), query, 0, packet.getLength());
                byte[] response = respond(query, false);
                if (response == null) {
                    continue;
                }
                udp.send(new DatagramPacket(response, response.length, packet.getAddress(), packet.getPort()));
            } catch (Exception e) {
                if (!running.get()) {
                    return;
                }
            }
        }
    }

    private void serveTcp() {
        while (running.get()) {
            try {
                Socket socket = tcp.accept();
                tcpPool.submit(() -> serveTcpClient(socket));
            } catch (Exception e) {
                return;
            }
        }
    }

    private void serveTcpClient(Socket socket) {
        try (socket) {
            socket.setSoTimeout(2_000);
            var in = new java.io.DataInputStream(socket.getInputStream());
            var out = new java.io.DataOutputStream(socket.getOutputStream());
            while (true) {
                int length;
                try {
                    length = in.readUnsignedShort();
                } catch (Exception e) {
                    return;
                }
                byte[] query = in.readNBytes(length);
                if (query.length < length) {
                    return;
                }
                boolean axfr = isAxfr(query);
                byte[] response = respond(query, true);
                if (response == null) {
                    return;
                }
                out.writeShort(response.length);
                out.write(response);
                out.flush();
                if (axfr) {
                    return;
                }
            }
        } catch (Exception ignored) {
            // Connect-only probes (tcp53Reachable) close without a query.
        }
    }

    private static boolean isAxfr(byte[] query) {
        try {
            Record question = new Message(query).getQuestion();
            return question != null && question.getType() == Type.AXFR;
        } catch (Exception e) {
            return false;
        }
    }

    static byte[] respond(byte[] queryBytes, boolean tcp) {
        try {
            Message query = new Message(queryBytes);
            Record question = query.getQuestion();
            if (question == null) {
                return wire(query, Rcode.FORMERR, List.of());
            }
            String name = question.getName().toString(true).toLowerCase(Locale.ROOT);
            int type = question.getType();
            if (type == Type.AXFR) {
                if (!tcp || !FixtureHosts.DNS_AXFR.equals(name)) {
                    return wire(query, Rcode.REFUSED, List.of());
                }
                return wire(query, Rcode.NOERROR, axfrRecords());
            }
            if (FIXTURE_HOSTS.contains(name)) {
                if (type == Type.A) {
                    return wire(query, Rcode.NOERROR, List.of(a(name, LOOPBACK)));
                }
                return wire(query, Rcode.NOERROR, List.of());
            }
            if (FixtureHosts.TYPOSQUAT_CANDIDATE.equals(name)) {
                if (type == Type.A) {
                    return wire(query, Rcode.NOERROR, List.of(a(name, BRAND_IP)));
                }
                if (type == Type.MX) {
                    return wire(query, Rcode.NOERROR, List.of(new MXRecord(abs(name), DClass.IN, TTL, 10, abs("mail.brand.net"))));
                }
                return wire(query, Rcode.NOERROR, List.of());
            }
            if ("mail.brand.net".equals(name)) {
                if (type == Type.A) {
                    return wire(query, Rcode.NOERROR, List.of(a(name, MAIL_IP)));
                }
                return wire(query, Rcode.NOERROR, List.of());
            }
            String zone = zoneOf(name);
            if (zone == null) {
                return wire(query, Rcode.NXDOMAIN, List.of());
            }
            List<Record> answers = zoneAnswers(zone, name, type);
            if (answers == null) {
                return wire(query, Rcode.REFUSED, List.of());
            }
            return wire(query, Rcode.NOERROR, answers);
        } catch (Exception e) {
            return null;
        }
    }

    /** Null means REFUSED. An empty list is NODATA. */
    private static List<Record> zoneAnswers(String zone, String name, int type) {
        if (type == Type.SOA && name.equals(zone)) {
            if (FixtureHosts.DNS_LAME.equals(zone)) {
                return null;
            }
            return List.of(soa(zone, FixtureHosts.DNS_BADMAIL.equals(zone) ? 2020010101L : 2026101501L));
        }
        if (type == Type.NS && name.equals(zone)) {
            return List.of(new NSRecord(abs(zone), DClass.IN, TTL, abs("ns1." + zone)));
        }
        if (type == Type.A && name.equals("ns1." + zone)) {
            return List.of(a(name, NS_IP));
        }
        if (!FixtureHosts.DNS_BADMAIL.equals(zone)) {
            return List.of();
        }
        if (type == Type.TXT && name.equals(zone)) {
            // Permissive record first: eleven "a" mechanisms plus one include is 12 lookups, and it ends in +all.
            return List.of(
                    txt(name, "v=spf1 a a a a a a a a a a a include:spf-gone.example +all"),
                    txt(name, "v=spf1 -all"));
        }
        if (type == Type.TXT && name.equals("_dmarc." + zone)) {
            return List.of(txt(name, "v=DMARC1; p=none; pct=50"));
        }
        if (type == Type.TXT && name.equals("default._domainkey." + zone)) {
            return List.of(txt(name, DKIM_TXT));
        }
        if (type == Type.MX && name.equals(zone)) {
            return List.of(new MXRecord(abs(name), DClass.IN, TTL, 10, abs("mail.gone.example")));
        }
        if (type == Type.A && name.startsWith("bh-wildcard-probe-") && name.endsWith("." + zone)) {
            return List.of(a(name, WILD_IP));
        }
        return List.of();
    }

    private static List<Record> axfrRecords() {
        String zone = FixtureHosts.DNS_AXFR;
        SOARecord first = soa(zone, 2026101501L);
        SOARecord last = soa(zone, 2026101501L);
        return List.of(
                first,
                new NSRecord(abs(zone), DClass.IN, TTL, abs("ns1." + zone)),
                a(zone, NS_IP),
                last);
    }

    private static String zoneOf(String name) {
        for (String zone : ZONES) {
            if (name.equals(zone) || name.endsWith("." + zone)) {
                return zone;
            }
        }
        return null;
    }

    private static byte[] wire(Message query, int rcode, List<Record> answers) {
        Message response = new Message(query.getHeader().getID());
        Header header = response.getHeader();
        header.setFlag(Flags.QR);
        if (rcode == Rcode.NOERROR) {
            header.setFlag(Flags.AA);
        }
        header.setRcode(rcode);
        Record question = query.getQuestion();
        if (question != null) {
            response.addRecord(question, Section.QUESTION);
        }
        for (Record answer : answers) {
            response.addRecord(answer, Section.ANSWER);
        }
        return response.toWire(65535);
    }

    private static SOARecord soa(String zone, long serial) {
        return new SOARecord(abs(zone), DClass.IN, TTL, abs("ns1." + zone), abs("hostmaster." + zone), serial, 3600, 600, 86400, 300);
    }

    private static ARecord a(String name, InetAddress address) {
        return new ARecord(abs(name), DClass.IN, TTL, address);
    }

    private static TXTRecord txt(String name, String value) {
        List<String> chunks = new ArrayList<>();
        for (int i = 0; i < value.length(); i += 255) {
            chunks.add(value.substring(i, Math.min(value.length(), i + 255)));
        }
        return new TXTRecord(abs(name), DClass.IN, TTL, chunks);
    }

    private static Name abs(String name) {
        try {
            return Name.fromString(name.endsWith(".") ? name : name + ".");
        } catch (Exception e) {
            throw new IllegalArgumentException(name, e);
        }
    }

    private static InetAddress address(int a, int b, int c, int d) {
        try {
            return InetAddress.getByAddress(new byte[] {(byte) a, (byte) b, (byte) c, (byte) d});
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String dkimTxt() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024);
            String encoded = Base64.getEncoder().encodeToString(generator.generateKeyPair().getPublic().getEncoded());
            return "v=DKIM1; k=rsa; p=" + encoded;
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    @Override
    public void close() {
        running.set(false);
        udp.close();
        try {
            tcp.close();
        } catch (Exception ignored) {
            // already closed
        }
        tcpPool.shutdownNow();
    }
}
