package org.freedonia.bloodhound.worker.modules.tls;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/** Pure interpretation of an already-fetched TlsFetchResult into findings - no network calls, fully unit-testable. */
public final class TlsDecisionLogic {

    private static final long EXPIRING_SOON_DAYS = 30;
    private static final long HSTS_MIN_MAX_AGE_SECONDS = 15_552_000; // 6 months
    private static final long HSTS_PRELOAD_MIN_MAX_AGE_SECONDS = 31_536_000; // 1 year - hstspreload.org's own submission bar
    private static final List<String> WEAK_CIPHER_MARKERS = List.of("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5");
    private static final Pattern MAX_AGE_PATTERN = Pattern.compile("max-age=(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final List<String> WEAK_SIGNATURE_MARKERS = List.of("MD5", "MD2", "SHA1");
    private static final int MIN_RSA_DSA_KEY_BITS = 2048;
    private static final List<String> FORWARD_SECRECY_MARKERS = List.of("ECDHE", "DHE");

    /**
     * Bounded allowlist of major public CA organization names as they
     * commonly appear in issuer DN "O=" fields, mirroring the weak-cipher
     * substring-list approach above. No per-organization-configurable CA
     * allowlist exists in this product yet (a real one would need to be a
     * whole feature of its own), so this is a pragmatic, hardcoded stand-in -
     * a certificate issued by a CA outside this list isn't necessarily
     * malicious, just unusual enough to be worth a human's attention.
     */
    private static final List<String> KNOWN_CA_MARKERS = List.of(
            "let's encrypt",
            "digicert",
            "sectigo",
            "comodo",
            "globalsign",
            "amazon",
            "google trust services",
            "microsoft",
            "godaddy",
            "cpanel",
            "zerossl",
            "entrust",
            "ssl.com",
            "identrust");

    private TlsDecisionLogic() {}

    public static List<RawFinding> decide(String hostname, TlsFetchResult r, Instant now) {
        List<RawFinding> findings = new ArrayList<>();

        if (r.certNotAfter() != null) {
            if (r.certNotAfter().isBefore(now)) {
                findings.add(finding(
                        "TLS_CERT_EXPIRED", Severity.CRITICAL, hostname, Map.of("notAfter", r.certNotAfter().toString())));
            } else if (r.certNotAfter().isBefore(now.plus(EXPIRING_SOON_DAYS, ChronoUnit.DAYS))) {
                findings.add(finding(
                        "TLS_CERT_EXPIRING_SOON", Severity.MEDIUM, hostname, Map.of("notAfter", r.certNotAfter().toString())));
            }
        }

        if (!r.chainTrusted()) {
            findings.add(finding("TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN", Severity.HIGH, hostname, Map.of()));
        }

        // "<host>: <protocol>" (the cookie rules' "<host>: <name>" convention), not the bare protocol
        // name this used to emit: findings dedupe on (rule, affected_asset) per target, so with the
        // hostname only in evidence, a second host in the same target supporting TLSv1 was silently
        // dropped as a duplicate of the first. Went unnoticed because the rule had never fired at all
        // until the probe itself was fixed (see LegacyTlsProbeSupport).
        if (r.sslv3Supported()) {
            findings.add(legacyProtocol(hostname, "SSLv3"));
            // POODLE (CVE-2014-3566) exploits SSLv3's own CBC-mode padding design directly - there
            // is no patch for this short of disabling SSLv3 entirely, so the protocol being
            // reachable at all (independent of which cipher suite actually gets negotiated) is
            // sufficient to conclude vulnerability, matching every major scanner's own treatment of
            // this specific named CVE. A distinct, explicitly-named finding (not just folded into
            // the generic legacy-protocol one above) closes a real gap found comparing this module
            // against Qualys SSL Labs/testssl.sh: a security team searching for "POODLE" by name
            // would otherwise find nothing here even though the exact same signal already exists.
            findings.add(finding("TLS_POODLE_VULNERABLE", Severity.CRITICAL, hostname, Map.of()));
        }
        if (r.tls1Supported()) {
            findings.add(legacyProtocol(hostname, "TLSv1"));
        }
        if (r.tls11Supported()) {
            findings.add(legacyProtocol(hostname, "TLSv1.1"));
        }

        // Positive-signal gap closed by a rules-comparison audit against Qualys SSL Labs (which caps
        // its grade at A- without TLS1.3): absence of any legacy-protocol finding above could mean
        // either "modern and clean" or "we never checked" - this makes that distinction explicit
        // rather than leaving it to be inferred from silence.
        if (!r.tls13Supported()) {
            findings.add(finding("TLS_1_3_NOT_SUPPORTED", Severity.LOW, hostname, Map.of()));
        }

        // Only evaluated when a protocol/cipher was actually captured (skipped for the weak-suite-
        // only path, where both are null) - and never for TLS1.3, whose own cipher suite names
        // (e.g. TLS_AES_128_GCM_SHA256) never encode a key-exchange algorithm at all, since every
        // TLS1.3 suite is inherently forward-secret by design. For 1.2 and earlier, the *server's*
        // choice from this client's offer (which includes both ECDHE/DHE and plain RSA/DH suites)
        // is a direct signal of what it prefers/requires - same reasoning WeakCipherProbe's own
        // javadoc gives for treating a modern client's negotiated suite as meaningful evidence.
        if (r.cipherSuite() != null
                && !"TLSv1.3".equals(r.negotiatedProtocol())
                && FORWARD_SECRECY_MARKERS.stream().noneMatch(r.cipherSuite().toUpperCase(Locale.ROOT)::contains)) {
            findings.add(finding(
                    "TLS_NO_FORWARD_SECRECY", Severity.MEDIUM, hostname, Map.of("cipherSuite", r.cipherSuite())));
        }

        // Two sources, one finding: the suite our own (strong-only) client negotiated can only be
        // weak if the server has nothing better; the WeakCipherProbe result is the direct test of
        // "will it accept a weak one if offered" and is what actually fires in practice - see
        // WeakCipherProbe for why the first check alone had never fired.
        if (r.weakCipherNegotiated() != null) {
            findings.add(finding(
                    "TLS_WEAK_CIPHER_SUITE",
                    Severity.MEDIUM,
                    hostname,
                    Map.of("cipherSuite", r.weakCipherNegotiated(), "offeredOnlyWeakSuites", true)));
        } else if (r.cipherSuite() != null && isWeakCipher(r.cipherSuite())) {
            findings.add(finding(
                    "TLS_WEAK_CIPHER_SUITE", Severity.MEDIUM, hostname, Map.of("cipherSuite", r.cipherSuite())));
        }

        if (r.httpsReachable()) {
            findings.addAll(hstsFindings(hostname, r.hstsHeaderValue(), r.hstsPreloadListStatus()));
        }

        if (r.certDnsNames() != null && !r.certDnsNames().isEmpty() && !certCovers(hostname, r.certDnsNames())) {
            findings.add(finding(
                    "TLS_CERT_HOSTNAME_MISMATCH",
                    Severity.HIGH,
                    hostname,
                    Map.of("hostname", hostname, "certificateNames", r.certDnsNames())));
        }

        // A rules-parity review found this rule_id's name overclaims: it is an issuer-allowlist
        // heuristic (isKnownIssuer checks the issuer DN against a short hardcoded list of major
        // public CA name substrings), not a Certificate Transparency log lookup - no CT log is
        // ever consulted here. The title/description below already describe it honestly
        // ("unrecognized CA", "outside a curated list") with no CT framing, which is the part a
        // user actually sees - renaming the bare rule_id itself was deliberately not done, since
        // it is this finding's identity (findings.rule_id, the per-org rule-disable override
        // table, and every historical/trend row already use it) and a rename would orphan all of
        // that for a cosmetic fix. Left as a known naming quirk.
        if (r.certIssuer() != null && !isKnownIssuer(r.certIssuer())) {
            findings.add(finding(
                    "TLS_CT_UNEXPECTED_ISSUER", Severity.MEDIUM, hostname, Map.of("issuer", r.certIssuer())));
        }

        if (r.certSignatureAlgorithm() != null && isWeakSignatureAlgorithm(r.certSignatureAlgorithm())) {
            findings.add(finding(
                    "TLS_CERT_SIGNATURE_ALGORITHM_WEAK",
                    Severity.HIGH,
                    hostname,
                    Map.of("signatureAlgorithm", r.certSignatureAlgorithm())));
        }

        if (isKeyTooShort(r.certPublicKeyAlgorithm(), r.certPublicKeyBits())) {
            findings.add(finding(
                    "TLS_CERT_KEY_TOO_SHORT",
                    Severity.HIGH,
                    hostname,
                    Map.of("publicKeyAlgorithm", r.certPublicKeyAlgorithm(), "publicKeyBits", r.certPublicKeyBits())));
        }

        return findings;
    }

    static boolean isWeakSignatureAlgorithm(String sigAlgName) {
        String upper = sigAlgName.toUpperCase(Locale.ROOT);
        return WEAK_SIGNATURE_MARKERS.stream().anyMatch(upper::contains);
    }

    /** Only RSA/DSA are evaluated against a fixed bit-length floor - see TlsFetcher's own javadoc on why an EC key's strength isn't comparable the same way. */
    static boolean isKeyTooShort(String publicKeyAlgorithm, Integer publicKeyBits) {
        if (publicKeyBits == null || publicKeyAlgorithm == null) {
            return false;
        }
        return ("RSA".equals(publicKeyAlgorithm) || "DSA".equals(publicKeyAlgorithm)) && publicKeyBits < MIN_RSA_DSA_KEY_BITS;
    }

    private static RawFinding legacyProtocol(String hostname, String protocol) {
        return finding(
                "TLS_WEAK_PROTOCOL_SUPPORTED",
                Severity.HIGH,
                hostname + ": " + protocol,
                Map.of("hostname", hostname, "protocol", protocol));
    }

    /**
     * RFC 6125 matching as browsers do it: exact match, or a wildcard whose single {@code *} is
     * the entire left-most label matching exactly one label ({@code *.example.com} covers
     * {@code a.example.com} but not {@code a.b.example.com} or {@code example.com}).
     */
    static boolean certCovers(String hostname, List<String> certNames) {
        String host = hostname.toLowerCase(Locale.ROOT);
        for (String name : certNames) {
            if (name.equals(host)) {
                return true;
            }
            if (name.startsWith("*.")) {
                String suffix = name.substring(1); // ".example.com"
                int firstDot = host.indexOf('.');
                if (firstDot > 0 && host.substring(firstDot).equals(suffix)) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean isKnownIssuer(String issuerDn) {
        String lower = issuerDn.toLowerCase(Locale.ROOT);
        return KNOWN_CA_MARKERS.stream().anyMatch(lower::contains);
    }

    private static List<RawFinding> hstsFindings(String hostname, String hstsHeaderValue, String preloadListStatus) {
        if (hstsHeaderValue == null) {
            return List.of(finding("TLS_NO_HSTS", Severity.MEDIUM, hostname, Map.of()));
        }
        List<RawFinding> findings = new ArrayList<>();
        long maxAge = parseMaxAge(hstsHeaderValue);
        String lower = hstsHeaderValue.toLowerCase(Locale.ROOT);
        boolean includesSubDomains = lower.contains("includesubdomains");
        if (maxAge < HSTS_MIN_MAX_AGE_SECONDS || !includesSubDomains) {
            findings.add(finding("TLS_HSTS_SHORT_MAX_AGE", Severity.LOW, hostname, Map.of("header", hstsHeaderValue)));
        }
        // A separate, stricter bar than the one above: hstspreload.org (the source of every
        // browser's built-in HSTS preload list) requires max-age >= 1 year (not the 6 months
        // checked above) plus includeSubDomains before it will even accept a submission. A site
        // that adds the "preload" token without actually meeting that bar gets neither a
        // TLS_HSTS_SHORT_MAX_AGE finding (it can clear the 6-month bar while still missing the
        // 1-year one) nor any real protection from the token - it's a false signal of readiness,
        // most often left over from a policy that was strong enough for preload once and has since
        // been weakened without removing the token. Confirmed live: github.com actually sends
        // "max-age=31536000; includeSubdomains; preload" (exactly at the eligible bar, no finding);
        // none of our other tracked targets send the preload token at all.
        if (lower.contains("preload") && (maxAge < HSTS_PRELOAD_MIN_MAX_AGE_SECONDS || !includesSubDomains)) {
            findings.add(finding(
                    "TLS_HSTS_PRELOAD_NOT_ELIGIBLE", Severity.LOW, hostname, Map.of("header", hstsHeaderValue)));
        }
        // Orthogonal to the eligibility check above: a site can technically clear hstspreload.org's
        // submission bar (or have cleared it once) without ever actually being on the real list
        // browsers ship - or have been removed from it since. The header's own claims say nothing
        // about this; only hstspreload.org's own status API does. preloadListStatus is null whenever
        // the header has no preload token at all (never queried) or the lookup itself failed - either
        // way, silence, not a finding, matching this codebase's own best-effort-signal precedent.
        if (lower.contains("preload") && preloadListStatus != null && !"preloaded".equals(preloadListStatus)) {
            findings.add(finding(
                    "TLS_HSTS_NOT_ON_PRELOAD_LIST",
                    Severity.LOW,
                    hostname,
                    Map.of("header", hstsHeaderValue, "preloadListStatus", preloadListStatus)));
        }
        return findings;
    }

    static long parseMaxAge(String hstsHeaderValue) {
        Matcher matcher = MAX_AGE_PATTERN.matcher(hstsHeaderValue);
        return matcher.find() ? Long.parseLong(matcher.group(1)) : 0;
    }

    static boolean isWeakCipher(String cipherSuite) {
        String upper = cipherSuite.toUpperCase(Locale.ROOT);
        return WEAK_CIPHER_MARKERS.stream().anyMatch(upper::contains);
    }

    private static RawFinding finding(String ruleId, Severity severity, String asset, Map<String, Object> evidence) {
        String[] copy = COPY.get(ruleId);
        return new RawFinding(ruleId, severity, Category.TLS, copy[0], copy[1], asset, evidence);
    }

    private static final Map<String, String[]> COPY = Map.ofEntries(
            Map.entry("TLS_CERT_EXPIRED",
                    new String[] {"TLS certificate expired", "The certificate presented for this host has already expired."}),
            Map.entry("TLS_CERT_EXPIRING_SOON",
                    new String[] {
                        "TLS certificate expiring soon", "The certificate presented for this host expires within 30 days."
                    }),
            Map.entry("TLS_CERT_SELF_SIGNED_OR_UNTRUSTED_CHAIN",
                    new String[] {
                        "Untrusted or self-signed TLS certificate chain",
                        "The certificate chain does not validate against a public trust root."
                    }),
            Map.entry("TLS_WEAK_PROTOCOL_SUPPORTED",
                    new String[] {"Legacy TLS protocol supported", "The server accepted a handshake using a deprecated TLS protocol version."}),
            Map.entry("TLS_POODLE_VULNERABLE",
                    new String[] {
                        "Vulnerable to POODLE (CVE-2014-3566)",
                        "This server still accepts SSLv3, whose CBC-mode cipher suites have a padding "
                                + "design flaw with no fix short of disabling the protocol entirely - an "
                                + "attacker able to intercept and manipulate traffic (e.g. on a shared network) "
                                + "can use repeated padding-oracle requests to decrypt small amounts of "
                                + "plaintext, such as session cookies, one byte at a time."
                    }),
            Map.entry("TLS_WEAK_CIPHER_SUITE",
                    new String[] {
                        "Weak TLS cipher suite accepted",
                        "The server is willing to negotiate a cipher suite using a known-weak algorithm (RC4, DES/3DES, "
                                + "export-grade, NULL encryption, or anonymous key exchange) when a client offers it."
                    }),
            Map.entry("TLS_NO_HSTS",
                    new String[] {"Missing HSTS header", "The response has no Strict-Transport-Security header."}),
            Map.entry("TLS_HSTS_SHORT_MAX_AGE",
                    new String[] {
                        "Weak HSTS policy",
                        "The Strict-Transport-Security header's max-age is under 6 months and/or missing includeSubDomains."
                    }),
            Map.entry("TLS_HSTS_PRELOAD_NOT_ELIGIBLE",
                    new String[] {
                        "HSTS preload token present without meeting preload requirements",
                        "The Strict-Transport-Security header includes the preload token, but hstspreload.org "
                                + "(the source of every browser's built-in preload list) requires max-age of at least "
                                + "1 year and includeSubDomains before it will accept a submission. The token gives a "
                                + "false sense of protection: browsers ignore it entirely unless the site is actually "
                                + "on the list, and it won't be while the underlying policy is this weak."
                    }),
            Map.entry("TLS_CERT_HOSTNAME_MISMATCH",
                    new String[] {
                        "TLS certificate does not match hostname",
                        "The certificate presented for this host is not valid for its name - none of its Subject "
                                + "Alternative Names cover it. Every browser and API client will refuse the connection "
                                + "(or users will be trained to click through warnings); the host is typically serving "
                                + "another site's certificate through a shared load balancer or a copy-pasted config."
                    }),
            Map.entry("TLS_CT_UNEXPECTED_ISSUER",
                    new String[] {
                        "Certificate issued by an unrecognized CA",
                        "The presented certificate was issued by a Certificate Authority outside a curated list of "
                                + "major, well-known public CAs. This can be entirely legitimate, but is also a "
                                + "pattern seen with MITM interception, phishing infrastructure impersonating this "
                                + "domain, or a misconfigured issuance pipeline - worth a human review."
                    }),
            Map.entry("TLS_CERT_SIGNATURE_ALGORITHM_WEAK",
                    new String[] {
                        "Certificate signed with a weak signature algorithm",
                        "The certificate is signed using MD5 or SHA-1, both of which are cryptographically broken "
                                + "for signature purposes and are no longer trusted by modern browsers - a "
                                + "forged certificate with a colliding signature is feasible for an attacker with "
                                + "sufficient resources."
                    }),
            Map.entry("TLS_CERT_KEY_TOO_SHORT",
                    new String[] {
                        "Certificate public key too short",
                        "The certificate's RSA/DSA public key is under 2048 bits, below the minimum modern CAs and "
                                + "browsers require - a key this size is within range of being factored, undermining "
                                + "every guarantee the certificate is meant to provide."
                    }),
            Map.entry("TLS_1_3_NOT_SUPPORTED",
                    new String[] {
                        "TLS 1.3 not supported",
                        "This host does not negotiate TLS 1.3, the current protocol version. Qualys SSL Labs caps "
                                + "its grade at A- for a server missing it - every supported connection is still "
                                + "using an older protocol generation, with weaker default cipher/handshake choices "
                                + "and strictly more historical attack surface than 1.3 was designed to remove."
                    }),
            Map.entry("TLS_NO_FORWARD_SECRECY",
                    new String[] {
                        "No forward secrecy",
                        "The negotiated cipher suite does not use an ephemeral (ECDHE/DHE) key exchange, meaning "
                                + "this connection's session key is derived from the server's long-term private key "
                                + "rather than a fresh per-session one. If that private key is ever compromised, "
                                + "every past session recorded by an eavesdropper (not just future ones) can be "
                                + "decrypted retroactively - the exact property forward secrecy exists to prevent."
                    }),
            Map.entry("TLS_HSTS_NOT_ON_PRELOAD_LIST",
                    new String[] {
                        "HSTS preload token present but domain is not on the real preload list",
                        "The Strict-Transport-Security header includes the preload token, but hstspreload.org's own "
                                + "status API confirms this domain is not actually included in the list browsers "
                                + "ship (it may never have been submitted, or may have since been removed). Unlike "
                                + "TLS_HSTS_PRELOAD_NOT_ELIGIBLE (which checks whether the header's own values meet "
                                + "the submission bar), this checks the real-world outcome: browsers give this site "
                                + "no preload protection regardless of how the header reads."
                    }));
}
