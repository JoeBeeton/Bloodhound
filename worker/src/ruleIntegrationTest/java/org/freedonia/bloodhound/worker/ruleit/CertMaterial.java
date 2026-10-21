package org.freedonia.bloodhound.worker.ruleit;

import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Vector;
import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DNSName;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

/**
 * Writes {@code server.p12} (aliases good, bad, soon) and {@code truststore.p12} (the CA only).
 * Always regenerated so notAfter stays relative to now. Run as a Gradle JavaExec, not from the test JVM.
 */
public final class CertMaterial {

    static final char[] PASSWORD = "changeit".toCharArray();
    private static final String CA_DN = "CN=BloodhoundRuleFixtureCA";
    private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1";

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: CertMaterial <output-dir>");
        }
        Path dir = Path.of(args[0]);
        Files.createDirectories(dir);

        KeyPair caKey = rsa(2048);
        X500Name caName = new X500Name(CA_DN);
        Instant now = Instant.now();
        X509Certificate caCert = sign(
                caName,
                caName,
                caKey.getPublic(),
                caKey.getPrivate(),
                true,
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                "SHA256withRSA",
                List.of());

        KeyPair goodKey = rsa(2048);
        X509Certificate good = sign(
                new X500Name("CN=BloodhoundRuleFixture"),
                caName,
                goodKey.getPublic(),
                caKey.getPrivate(),
                false,
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(90, ChronoUnit.DAYS)),
                "SHA256withRSA",
                FixtureHosts.GOOD_CERT_NAMES);

        Issued bad = issueBad(now);
        KeyPair soonKey = rsa(2048);
        X509Certificate soon = sign(
                new X500Name("CN=" + FixtureHosts.TLS_SOON),
                caName,
                soonKey.getPublic(),
                caKey.getPrivate(),
                false,
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(10, ChronoUnit.DAYS)),
                "SHA256withRSA",
                List.of(FixtureHosts.TLS_SOON));

        KeyStore server = KeyStore.getInstance("PKCS12");
        server.load(null, PASSWORD);
        server.setKeyEntry("good", goodKey.getPrivate(), PASSWORD, new Certificate[] {good, caCert});
        server.setKeyEntry("bad", bad.privateKey(), PASSWORD, new Certificate[] {bad.certificate()});
        server.setKeyEntry("soon", soonKey.getPrivate(), PASSWORD, new Certificate[] {soon, caCert});
        try (OutputStream out = Files.newOutputStream(dir.resolve("server.p12"))) {
            server.store(out, PASSWORD);
        }

        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, PASSWORD);
        trust.setCertificateEntry("ca", caCert);
        try (OutputStream out = Files.newOutputStream(dir.resolve("truststore.p12"))) {
            trust.store(out, PASSWORD);
        }

        Properties props = new Properties();
        props.setProperty("badSigAlg", bad.certificate().getSigAlgName());
        props.setProperty(
                "badKeyBits",
                Integer.toString(((java.security.interfaces.RSAPublicKey) bad.certificate().getPublicKey())
                        .getModulus()
                        .bitLength()));
        try (OutputStream out = Files.newOutputStream(dir.resolve("material.properties"))) {
            props.store(out, "generated certificate properties the TLS test conditions on");
        }
    }

    /** Self-signed, already expired, SAN that does not cover the host. SHA1 and a 1024-bit key when this JDK will sign them. */
    private static Issued issueBad(Instant now) throws Exception {
        int bits = 1024;
        String sig = "SHA1withRSA";
        KeyPair key;
        X509Certificate cert;
        try {
            key = rsa(bits);
            X500Name subject = new X500Name("CN=" + FixtureHosts.TLS_BAD);
            cert = sign(
                    subject,
                    subject,
                    key.getPublic(),
                    key.getPrivate(),
                    false,
                    Date.from(now.minus(30, ChronoUnit.DAYS)),
                    Date.from(now.minus(1, ChronoUnit.DAYS)),
                    sig,
                    List.of("unrelated.example"));
        } catch (Exception sha1Failed) {
            bits = 2048;
            sig = "SHA256withRSA";
            key = rsa(bits);
            X500Name subject = new X500Name("CN=" + FixtureHosts.TLS_BAD);
            cert = sign(
                    subject,
                    subject,
                    key.getPublic(),
                    key.getPrivate(),
                    false,
                    Date.from(now.minus(30, ChronoUnit.DAYS)),
                    Date.from(now.minus(1, ChronoUnit.DAYS)),
                    sig,
                    List.of("unrelated.example"));
        }
        return new Issued(key.getPrivate(), cert);
    }

    private static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits, new SecureRandom());
        return generator.generateKeyPair();
    }

    private static X509Certificate sign(
            X500Name subject,
            X500Name issuer,
            PublicKey publicKey,
            PrivateKey privateKey,
            boolean ca,
            Date notBefore,
            Date notAfter,
            String sigAlg,
            List<String> dnsNames)
            throws Exception {
        X509CertInfo info = new X509CertInfo();
        info.setVersion(new CertificateVersion(CertificateVersion.V3));
        info.setSerialNumber(new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        info.setSubject(subject);
        info.setIssuer(issuer);
        info.setValidity(new CertificateValidity(notBefore, notAfter));
        info.setKey(new CertificateX509Key(publicKey));
        info.setAlgorithmId(new CertificateAlgorithmId(AlgorithmId.get(sigAlg)));

        CertificateExtensions extensions = new CertificateExtensions();
        extensions.setExtension(
                BasicConstraintsExtension.NAME,
                new BasicConstraintsExtension(Boolean.valueOf(ca), ca, ca ? 0 : -1));
        boolean[] usage = new boolean[9];
        if (ca) {
            usage[5] = true;
        } else {
            usage[0] = true;
            usage[2] = true;
        }
        extensions.setExtension(KeyUsageExtension.NAME, new KeyUsageExtension(usage));
        if (!ca) {
            Vector<ObjectIdentifier> eku = new Vector<>();
            eku.add(ObjectIdentifier.of(SERVER_AUTH));
            extensions.setExtension(
                    ExtendedKeyUsageExtension.NAME, new ExtendedKeyUsageExtension(Boolean.FALSE, eku));
        }
        if (!dnsNames.isEmpty()) {
            GeneralNames names = new GeneralNames();
            for (String dns : dnsNames) {
                names.add(new GeneralName(new DNSName(dns)));
            }
            extensions.setExtension(
                    SubjectAlternativeNameExtension.NAME,
                    new SubjectAlternativeNameExtension(Boolean.FALSE, names));
        }
        info.setExtensions(extensions);
        return X509CertImpl.newSigned(info, privateKey, sigAlg);
    }

    private record Issued(PrivateKey privateKey, X509Certificate certificate) {}

    private CertMaterial() {}
}
