package org.freedonia.bloodhound.worker.ruleit;

import java.util.List;

/** Bare hostnames. A name that already contains a port makes exposure alt-port URLs invalid. */
public final class FixtureHosts {

    public static final String HEADERS_MISSING = "headers-missing.bh.test";
    public static final String HEADERS_CSP = "headers-csp.bh.test";
    public static final String EXPOSURE = "exposure.bh.test";
    public static final String EXPOSURE_INDEX = "exposure-index.bh.test";
    public static final String DOCS = "docs.bh.test";
    public static final String TLS_BAD = "tls-bad.bh.test";
    public static final String TLS_SOON = "tls-soon.bh.test";
    public static final String TLS_HSTS_NONE = "tls-hsts-none.bh.test";
    public static final String TLS_HSTS_SHORT = "tls-hsts-short.bh.test";
    public static final String TLS_HSTS_PRELOAD = "tls-hsts-preload.bh.test";
    public static final String PORTS_ONE = "ports-one.bh.test";
    public static final String PORTS_MANY = "ports-many.bh.test";

    /** DNS-only zones. Not on the SSRF allowlist and not on the trusted certificate. */
    public static final String DNS_ABSENT = "absent.bh.test";
    public static final String DNS_BADMAIL = "badmail.bh.test";
    public static final String DNS_AXFR = "axfr.bh.test";
    public static final String DNS_LAME = "lame.bh.test";

    /** Typosquat root. Must stay unresolved so the SSRF check treats it as an unknown host. */
    public static final String TYPOSQUAT_ROOT = "brand.test";
    /** First TLD swap PermutationGenerator emits for a {@code .test} root. */
    public static final String TYPOSQUAT_CANDIDATE = "brand.net";

    public static final List<String> SCANNED = List.of(
            HEADERS_MISSING,
            HEADERS_CSP,
            EXPOSURE,
            EXPOSURE_INDEX,
            DOCS,
            TLS_BAD,
            TLS_SOON,
            TLS_HSTS_NONE,
            TLS_HSTS_SHORT,
            TLS_HSTS_PRELOAD,
            PORTS_ONE,
            PORTS_MANY);

    /** Every host HttpClient will open over HTTPS except the two that carry their own certificates. */
    public static final List<String> GOOD_CERT_NAMES = List.of(
            HEADERS_MISSING,
            HEADERS_CSP,
            EXPOSURE,
            EXPOSURE_INDEX,
            DOCS,
            TLS_HSTS_NONE,
            TLS_HSTS_SHORT,
            TLS_HSTS_PRELOAD,
            PORTS_ONE,
            PORTS_MANY);

    private FixtureHosts() {}
}
