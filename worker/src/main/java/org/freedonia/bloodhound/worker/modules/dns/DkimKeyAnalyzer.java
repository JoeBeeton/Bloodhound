package org.freedonia.bloodhound.worker.modules.dns;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Locale;
import java.util.Optional;

/**
 * Pure parsing of one DKIM TXT record's own public key strength - no network calls. A DKIM TXT
 * value is {@code ;}-separated {@code tag=value} pairs (RFC 6376 3.6.1); the one this cares about
 * is {@code p=}, the base64-encoded public key in X.509 SubjectPublicKeyInfo form for the default
 * (and by far most common) {@code k=rsa} key type - which the JDK's own {@link X509EncodedKeySpec}
 * parses directly into an {@link RSAPublicKey}, giving the real modulus bit length with no manual
 * ASN.1/DER byte-scraping needed. Verified live against two real DKIM records before building
 * this: github.com's {@code google} selector carries a 2048-bit key, Microsoft's {@code selector2}
 * (onmicrosoft.com) carries a 1024-bit key - both parsed correctly by this exact approach.
 */
final class DkimKeyAnalyzer {

    private DkimKeyAnalyzer() {}

    /**
     * Empty when: the record isn't an RSA key (ed25519 keys are a fixed, inherently strong 256
     * bits and not a candidate for a "weak key" check at all), the {@code p=} tag is missing or
     * empty (an empty {@code p=} specifically means "this key is revoked" per RFC 6376 3.6.1 -
     * a different, already-dead-key condition, not a weak-but-live one), or the value isn't
     * parseable as a DER-encoded RSA public key at all (malformed record - no finding, not a guess).
     */
    static Optional<Integer> rsaKeyBitLength(String dkimTxtValue) {
        if (dkimTxtValue == null) {
            return Optional.empty();
        }
        String keyType = tagValue(dkimTxtValue, "k");
        if (keyType != null && !keyType.equalsIgnoreCase("rsa")) {
            return Optional.empty();
        }
        String publicKey = tagValue(dkimTxtValue, "p");
        if (publicKey == null || publicKey.isBlank()) {
            return Optional.empty();
        }
        try {
            byte[] der = Base64.getDecoder().decode(publicKey.replaceAll("\\s+", ""));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            RSAPublicKey key = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
            return Optional.of(key.getModulus().bitLength());
        } catch (Exception malformed) {
            return Optional.empty();
        }
    }

    private static String tagValue(String dkimTxtValue, String tag) {
        for (String part : dkimTxtValue.split(";")) {
            String trimmed = part.trim();
            int eq = trimmed.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String name = trimmed.substring(0, eq).trim().toLowerCase(Locale.ROOT);
            if (name.equals(tag)) {
                return trimmed.substring(eq + 1).trim();
            }
        }
        return null;
    }
}
