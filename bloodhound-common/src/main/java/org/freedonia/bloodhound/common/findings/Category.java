package org.freedonia.bloodhound.common.findings;

public enum Category {
    TLS,
    DNS,
    HEADERS,
    EXPOSURE,
    SUBDOMAIN_HYGIENE,
    NETWORK,
    WHOIS,
    BREACH,
    /** ZAP active-scan alerts (Tier 2). Deliberately outside ScoringEngine's fixed weight table, same precedent as WHOIS/BREACH - shows up in findings/UI, never affects the score. */
    WEB_APP,
    /** Typosquat/lookalike-domain brand-protection findings. Same precedent as WHOIS/BREACH/WEB_APP - not one of the target's own infrastructure categories, so outside ScoringEngine's fixed weight table by design. */
    BRAND,
    /** Synthesized compound-risk findings (CompoundRiskAnalysisService) describing a dangerous co-occurrence of two or more primary findings on the same asset. A prioritization/insight layer over the score, not an input to it - same WHOIS/BREACH/WEB_APP/BRAND precedent, outside ScoringEngine's fixed weight table by design (double-counting the underlying findings' severity would be wrong). */
    COMPOUND
}
