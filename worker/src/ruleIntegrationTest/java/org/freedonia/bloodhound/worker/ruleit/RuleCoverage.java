package org.freedonia.bloodhound.worker.ruleit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Rules this suite does not claim. Each one needs a third party, a binary that is not installed
 * (naabu, zgrab2, nuclei), or a finding whose inputs cannot be produced from the local fixture.
 * Unseeded families ZAP_ALERT_* and NUCLEI_* are the same kind of gap.
 */
class RuleCoverage {

    static final Set<String> NOT_LOCAL = Set.of(
            "BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH",
            "NETWORK_IP_KNOWN_BOTNET_C2",
            "NETWORK_ANONYMOUS_FTP",
            "NETWORK_FULL_PORT_SURFACE",
            "NETWORK_SSH_WEAK_ALGORITHM_SUPPORTED",
            "BRAND_IMPERSONATING_APP_DETECTED",
            "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE",
            "TLS_HSTS_NOT_ON_PRELOAD_LIST",
            "TLS_NO_FORWARD_SECRECY",
            "TLS_WEAK_CIPHER_SUITE",
            "WHOIS_EXPIRY_APPROACHING",
            "WHOIS_REGISTRANT_CHANGED",
            "WHOIS_NO_TRANSFER_LOCK",
            "SUBDOMAIN_DANGLING_CNAME",
            "SUBDOMAIN_NS_DELEGATION_TAKEOVER",
            "SUBDOMAIN_NEW_UNEXPECTED",
            "SUBDOMAIN_STALE_NOT_RESOLVING",
            "EXPOSURE_CLOUD_BUCKET_PUBLIC_LISTING",
            "EXPOSURE_CLOUD_BUCKET_BRUTEFORCE_DISCOVERED_PUBLIC",
            "TECH_KNOWN_CVE",
            "TECH_KNOWN_EXPLOITED_VULNERABILITY",
            "TECH_EOL_SOFTWARE_DETECTED",
            "TECH_EOL_APPROACHING",
            "COMPOUND_CREDENTIAL_TO_DATA_PIVOT",
            "COMPOUND_CONTAINER_ESCAPE_AMPLIFICATION",
            "COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE");

    /** A sample of rules the fixture tests require. The gap list must not swallow them. */
    private static final Set<String> LOCAL = Set.of(
            "HEADER_CSP_MISSING",
            "HEADER_CSP_WEAK_POLICY",
            "HTTP_NO_HTTPS_REDIRECT",
            "CORS_CREDENTIALED_ORIGIN_REFLECTION",
            "HTTP_TRACE_METHOD_ENABLED",
            "COOKIE_MISSING_HOST_PREFIX",
            "EXPOSURE_GIT_CONFIG",
            "EXPOSURE_ENV_FILE",
            "EXPOSURE_REDIS_UNAUTH",
            "EXPOSURE_DOCKER_API",
            "EXPOSURE_JS_SOURCE_MAP",
            "EXPOSURE_LIVE_SECRET_DETECTED",
            "EXPOSURE_ACTUATOR_INDEX",
            "EXPOSURE_ACTUATOR_HEALTH",
            "EXPOSURE_ACTUATOR_HEALTH_DETAILS",
            "DNS_SPF_MISSING",
            "DNS_SPF_TOO_PERMISSIVE",
            "DNS_DMARC_MISSING",
            "DNS_ZONE_TRANSFER_ALLOWED",
            "DNS_NS_LAME_DELEGATION",
            "DNS_DKIM_WEAK_KEY",
            "SUBDOMAIN_WILDCARD_DNS",
            "EMAIL_MTA_STS_MISSING",
            "TLS_CERT_EXPIRED",
            "TLS_CERT_EXPIRING_SOON",
            "TLS_NO_HSTS",
            "TLS_HSTS_SHORT_MAX_AGE",
            "TLS_HSTS_PRELOAD_NOT_ELIGIBLE",
            "TLS_1_3_NOT_SUPPORTED",
            "TLS_CT_UNEXPECTED_ISSUER",
            "PORT_UNEXPECTED_OPEN_ADMIN_SERVICE",
            "PORT_OPEN_UNENCRYPTED_MGMT",
            "NETWORK_PROMISCUOUS_PORT_RESPONSE",
            "EXPOSURE_DOCUMENT_METADATA_PATH_LEAK",
            "EXPOSURE_DOCUMENT_METADATA_AUTHOR_INFO",
            "TYPOSQUAT_DOMAIN_REGISTERED",
            "BRAND_TYPOSQUAT_MX_CONFIGURED",
            "COMPOUND_SOURCE_AND_CREDENTIAL_EXPOSURE",
            "COMPOUND_INTERCEPTABLE_ADMIN_ACCESS");

    @Test
    void gapListDoesNotIncludeRulesTheFixtureFires() {
        assertThat(NOT_LOCAL).doesNotContainAnyElementsOf(LOCAL);
        assertThat(NOT_LOCAL).contains(
                "BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH",
                "NETWORK_ANONYMOUS_FTP",
                "NETWORK_FULL_PORT_SURFACE",
                "TLS_HSTS_NOT_ON_PRELOAD_LIST",
                "TLS_WEAK_CIPHER_SUITE",
                "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE",
                "COMPOUND_ACTIVELY_EXPLOITED_EXPOSURE");
    }
}
