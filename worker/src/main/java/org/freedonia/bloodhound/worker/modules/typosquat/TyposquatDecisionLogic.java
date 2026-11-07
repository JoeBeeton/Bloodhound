package org.freedonia.bloodhound.worker.modules.typosquat;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.freedonia.bloodhound.common.findings.Category;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.freedonia.bloodhound.common.findings.Severity;

/**
 * Pure decision half: a checked candidate becomes a finding purely because it
 * resolves (registered + live) - registration alone is the actionable
 * signal, per the product decision that proving active phishing content is a
 * separate, paid-tooling-dependent capability out of scope here. No database
 * access, no "is this new" comparison needed (unlike SubdomainIngestionService's
 * findings): whether a candidate is registered is knowable from this scan
 * alone, so the module emits these findings directly rather than routing
 * through a central-server ingestion detour the way SUBDOMAIN_ENUM/WHOIS do.
 *
 * <p>A candidate flagged {@code wildcardArtifact} by {@link TyposquatChecker}
 * is never emitted as a finding, even though it technically resolves: that
 * resolution came from its parent zone answering for literally any
 * subdomain, not from anyone registering this specific lookalike label - not
 * real typosquatting signal, just noise from an unrelated wildcarded zone.
 *
 * <p>A {@link Disposition#BRAND_CONTROLLED} candidate is never emitted either, and parked,
 * redirect-to-brand and corporate-registrar ones get a single LOW/INFO registration finding with
 * no MX/live-site escalations - a prod review found ~95 of 127 lookalikes flagged HIGH/CRITICAL
 * were exactly these.
 */
public final class TyposquatDecisionLogic {

    /** What a resolving lookalike evidently is, before any severity is decided. */
    public enum Disposition {
        UNKNOWN,
        /** Mails into the brand's own servers or shares its dedicated nameservers - never reported. */
        BRAND_CONTROLLED,
        /** Its homepage lands on the brand's own site - very likely the brand's, reported as INFO. */
        REDIRECTS_TO_BRAND,
        /** Held at a corporate brand-protection registrar - usually a defensive registration, INFO. */
        CORPORATE_REGISTRAR,
        /** Parked or listed for sale - a registered lookalike, but no active use. LOW. */
        PARKED
    }

    /** Registered this recently, a lookalike staged for mail is much more likely fresh phishing infrastructure than a years-old unrelated business. */
    static final Duration RECENT_REGISTRATION = Duration.ofDays(90);

    /** See ScreenshotSimilarity: unrelated pages topped out at 55 (same-template pages ~65), real copies started at 72. */
    static final int CLONE_SIMILARITY_PERCENT = 70;

    /**
     * Mail hosts serving huge numbers of unrelated domains - a lookalike on Google Workspace says
     * nothing about it belonging to a brand that also happens to use Google Workspace.
     */
    private static final List<String> SHARED_MAIL_PROVIDER_SUFFIXES = List.of(
            "google.com", "googlemail.com", "outlook.com", "zoho.com", "zoho.eu", "icloud.com",
            "yahoodns.net", "protonmail.ch", "messagingengine.com", "mimecast.com", "messagelabs.com",
            "secureserver.net", "privateemail.com", "hostedemail.com", "emailsrvr.com", "ionos.com",
            "ionos.co.uk", "ovh.net", "amazonaws.com", "mailgun.org", "sendgrid.net", "porkbun.com",
            "titan.email", "yandex.net", "improvmx.com", "forwardemail.net", "stackmail.com",
            "hostinger.com", "beget.com");

    /** Nameservers/MX that only parking services and domain marketplaces hand out (observed on prod's parked lookalikes). */
    static final List<String> PARKING_DNS_SUFFIXES = List.of(
            "afternic.com", "abovedomains.com", "above.com", "parklogic.com", "hostedmxserver.com",
            "atom.com", "giantpanda.com", "mailerhost.net", "dns-parking.com", "sedo.com",
            "sedoparking.com", "bodis.com", "parkingcrew.net", "dan.com", "fabulous.com",
            "cashparking.com", "nameshift.com", "sawsells.com", "aftermarket.com");

    /** Corporate brand-protection registrars - their DNS/mail forwarding on a lookalike usually means a defensive registration. */
    static final List<String> CORPORATE_REGISTRAR_SUFFIXES = List.of(
            "cscdns.net", "cscdns.uk", "markmonitor.com", "comlaude-dns.com", "comlaude-dns.net",
            "comlaude-dns.eu", "safenames.net");

    /**
     * Nameserver hosts that big registrars/parking services hand out, identically, to huge numbers
     * of unrelated customers (Namecheap's dns1/dns2.registrar-servers.com is literally the same
     * pair for everyone) - two domains sharing these says nothing about common ownership.
     * Cloudflare is here too: its per-account nameserver pairs come from a shared pool, so
     * unrelated accounts regularly get the same pair.
     */
    private static final List<String> SHARED_NAMESERVER_SUFFIXES = List.of(
            "registrar-servers.com",
            "domaincontrol.com",
            "ns.cloudflare.com",
            "afternic.com",
            "sedoparking.com",
            "parkingcrew.net",
            "bodis.com",
            "above.com",
            "dan.com",
            "namebrightdns.com",
            "googledomains.com",
            "name-services.com",
            "hostinger.com",
            "squarespacedns.com",
            "wixdns.net");

    private TyposquatDecisionLogic() {}

    /**
     * True when the candidate is evidently run by the brand itself: any of its MX hosts is one of
     * the brand's own MX hosts or sits under the brand's own domain, or its nameserver set is
     * identical to the brand's and isn't one of the mass-shared registrar/parking pools above.
     */
    public static boolean isBrandControlled(
            String brandDomain,
            List<String> brandMxHosts,
            List<String> brandNameServers,
            List<String> candidateMxHosts,
            List<String> candidateNameServers) {
        String brand = normalize(brandDomain);
        Set<String> brandMx = normalizeAll(brandMxHosts);
        for (String mx : normalizeAll(candidateMxHosts)) {
            boolean sharedBrandMx = brandMx.contains(mx) && !hostUnderAny(mx, SHARED_MAIL_PROVIDER_SUFFIXES);
            if (sharedBrandMx || hostUnderAny(mx, List.of(brand))) {
                return true;
            }
        }
        Set<String> brandNs = normalizeAll(brandNameServers);
        Set<String> candidateNs = normalizeAll(candidateNameServers);
        return !brandNs.isEmpty()
                && brandNs.equals(candidateNs)
                && brandNs.stream().noneMatch(TyposquatDecisionLogic::isSharedNameServer);
    }

    /** {@code page} may be null when the homepage couldn't be fetched. */
    public static Disposition classify(
            String brandDomain,
            List<String> brandMxHosts,
            List<String> brandNameServers,
            List<String> candidateMxHosts,
            List<String> candidateNameServers,
            TyposquatPageProbe.PageInfo page) {
        if (isBrandControlled(brandDomain, brandMxHosts, brandNameServers, candidateMxHosts, candidateNameServers)) {
            return Disposition.BRAND_CONTROLLED;
        }
        if (page != null && page.landingHost() != null
                && hostUnderAny(page.landingHost(), List.of(normalize(brandDomain)))) {
            return Disposition.REDIRECTS_TO_BRAND;
        }
        Set<String> dnsHosts = normalizeAll(candidateNameServers);
        dnsHosts.addAll(normalizeAll(candidateMxHosts));
        if (dnsHosts.stream().anyMatch(h -> hostUnderAny(h, CORPORATE_REGISTRAR_SUFFIXES))) {
            return Disposition.CORPORATE_REGISTRAR;
        }
        if ((page != null && page.parkingPage()) || dnsHosts.stream().anyMatch(h -> hostUnderAny(h, PARKING_DNS_SUFFIXES))) {
            return Disposition.PARKED;
        }
        return Disposition.UNKNOWN;
    }

    static boolean hostUnderAny(String host, List<String> domains) {
        String h = normalize(host);
        return domains.stream().anyMatch(d -> h.equals(d) || h.endsWith("." + d));
    }

    private static boolean isSharedNameServer(String ns) {
        return hostUnderAny(ns, SHARED_NAMESERVER_SUFFIXES);
    }

    private static Set<String> normalizeAll(List<String> hosts) {
        Set<String> out = new HashSet<>();
        for (String host : hosts) {
            String n = normalize(host);
            if (!n.isEmpty()) {
                out.add(n);
            }
        }
        return out;
    }

    private static String normalize(String host) {
        if (host == null) {
            return "";
        }
        String n = host.trim().toLowerCase(Locale.ROOT);
        return n.endsWith(".") ? n.substring(0, n.length() - 1) : n;
    }

    public static List<RawFinding> decide(List<TyposquatChecker.CheckedCandidate> checked) {
        return decide(checked, Instant.now());
    }

    static List<RawFinding> decide(List<TyposquatChecker.CheckedCandidate> checked, Instant now) {
        List<RawFinding> findings = new ArrayList<>();
        for (TyposquatChecker.CheckedCandidate candidate : checked) {
            if (candidate.resolvedIps().isEmpty()
                    || candidate.wildcardArtifact()
                    || candidate.disposition() == Disposition.BRAND_CONTROLLED) {
                continue;
            }
            if (candidate.disposition() != Disposition.UNKNOWN) {
                findings.add(lowRiskRegistration(candidate));
                continue;
            }
            boolean looksLikeClone = candidate.visualSimilarityPercent() != null
                    && candidate.visualSimilarityPercent() >= CLONE_SIMILARITY_PERCENT;
            boolean recentlyRegistered = candidate.registrationDate() != null
                    && candidate.registrationDate().isAfter(now.minus(RECENT_REGISTRATION));
            Map<String, Object> evidence = new LinkedHashMap<>();
            evidence.put("permutationType", candidate.permutationType());
            evidence.put("resolvedIps", candidate.resolvedIps());
            if (candidate.registrationDate() != null) {
                evidence.put("registrationDate", candidate.registrationDate().toString());
            }
            if (candidate.visualSimilarityPercent() != null) {
                evidence.put("visualSimilarityPercent", candidate.visualSimilarityPercent());
            }
            String humanType =
                    candidate.permutationType().toLowerCase(Locale.ROOT).replace('_', ' ');
            String description = "A domain closely resembling this target's own (a " + humanType
                    + " variant) is registered and actively resolving, which is consistent with "
                    + "typosquatting or brand-impersonation infrastructure - though it can occasionally be "
                    + "a coincidentally similarly-named, unrelated legitimate site.";
            if (candidate.visualSimilarityPercent() != null) {
                description += " Its homepage's visual layout is " + candidate.visualSimilarityPercent()
                        + "% similar to the real target's, based on a screenshot comparison - "
                        + (candidate.visualSimilarityPercent() >= CLONE_SIMILARITY_PERCENT
                                ? "a strong additional signal that this may be an actual clone/impersonation, not just a coincidental name."
                                : "a comparatively weak visual match, which leans toward coincidental naming rather than a rendered clone.");
            }
            findings.add(new RawFinding(
                    "TYPOSQUAT_DOMAIN_REGISTERED",
                    Severity.HIGH,
                    Category.BRAND,
                    "Registered lookalike domain: " + candidate.domain(),
                    description,
                    candidate.domain(),
                    evidence));

            // Escalations of the base finding above, not alternatives to it - a parked
            // registration and one actively staged to receive phishing-reply mail or serve a
            // cloned login page are very different risk tiers, even though both trip
            // TYPOSQUAT_DOMAIN_REGISTERED first.
            // CRITICAL only with corroboration (a fresh registration or a visual clone) - plenty of
            // long-standing, unrelated businesses on a similar name have mail configured, and a
            // review found MX alone flagging those CRITICAL. Without corroboration it's HIGH, the
            // same tier as the registration itself.
            if (candidate.mxConfigured()) {
                Severity mxSeverity = recentlyRegistered || looksLikeClone ? Severity.CRITICAL : Severity.HIGH;
                Map<String, Object> mxEvidence = new LinkedHashMap<>();
                mxEvidence.put("permutationType", candidate.permutationType());
                if (candidate.registrationDate() != null) {
                    mxEvidence.put("registrationDate", candidate.registrationDate().toString());
                }
                findings.add(new RawFinding(
                        "BRAND_TYPOSQUAT_MX_CONFIGURED",
                        mxSeverity,
                        Category.BRAND,
                        "Lookalike domain has mail servers configured: " + candidate.domain(),
                        "This registered lookalike domain (a " + humanType + " variant of this target's own) has "
                                + "MX records configured - it isn't just parked, it's set up to receive email"
                                + (recentlyRegistered
                                        ? ", and it was registered within the last " + RECENT_REGISTRATION.toDays()
                                                + " days. That combination is consistent with actively staging the "
                                                + "domain for phishing-reply capture or business-email-compromise."
                                        : ". Its mail isn't routed to this brand's own mail servers, so it isn't "
                                                + "one of the brand's own defensive registrations - though a long-"
                                                + "established, unrelated business on a similar name looks the same "
                                                + "from DNS alone."),
                        candidate.domain(),
                        mxEvidence));
            }
            // screenshotPng is only ever attempted for a genuine candidate once the real target's
            // OWN screenshot has already succeeded (see check() above) - so, same caveat the
            // existing visualSimilarityPercent signal already carries, a transient screenshotter
            // failure on the real site suppresses this finding for every candidate in the batch,
            // not just a missed comparison score. Best-effort, not a guarantee.
            if (candidate.screenshotPng() != null) {
                // CRITICAL only when the visual-similarity comparison itself says this looks like
                // a clone (same >= 80 threshold the description text above already treats as "a
                // strong additional signal") - a security review found every live-site CRITICAL it
                // spot-checked where the comparison was weak or unavailable turned out to be an
                // unrelated, coincidentally-named real business or a parked/for-sale page, not
                // impersonation. "Hosts a live, renderable page" alone is real signal - a lookalike
                // domain going from parked to actively serving content is worth knowing about - just
                // not CRITICAL-alarm-worthy on its own without the visual-clone evidence to back it.
                Severity liveSiteSeverity = looksLikeClone ? Severity.CRITICAL : Severity.HIGH;
                findings.add(new RawFinding(
                        "BRAND_TYPOSQUAT_HOSTING_LIVE_SITE",
                        liveSiteSeverity,
                        Category.BRAND,
                        "Lookalike domain is hosting a live website: " + candidate.domain(),
                        "This registered lookalike domain (a " + humanType + " variant of this target's own) is "
                                + "serving a live, renderable web page - not just holding a DNS record. Combined "
                                + "with " + (candidate.visualSimilarityPercent() != null
                                        ? "a " + candidate.visualSimilarityPercent() + "% visual-similarity match to the real site, "
                                        : "the registration itself, ")
                                + "this is consistent with active phishing/impersonation content, not a parked or "
                                + "defensively-registered domain.",
                        candidate.domain(),
                        Map.of("permutationType", candidate.permutationType())));
            }
        }
        return findings;
    }

    /** The registration alone, without the MX/live-site escalations - see {@link Disposition}. */
    private static RawFinding lowRiskRegistration(TyposquatChecker.CheckedCandidate candidate) {
        String humanType = candidate.permutationType().toLowerCase(Locale.ROOT).replace('_', ' ');
        String what = "A domain closely resembling this target's own (a " + humanType + " variant) is registered";
        String description;
        Severity severity;
        switch (candidate.disposition()) {
            case PARKED -> {
                severity = Severity.LOW;
                description = what + ", but it is parked or listed for sale rather than serving its own content or "
                        + "handling mail. No sign of active abuse; worth acquiring or monitoring in case it changes "
                        + "hands.";
            }
            case REDIRECTS_TO_BRAND -> {
                severity = Severity.INFO;
                description = what + " and its homepage lands on this target's own site, so it is very likely one "
                        + "of the brand's own defensive registrations. Confirm it is held by the brand.";
            }
            case CORPORATE_REGISTRAR -> {
                severity = Severity.INFO;
                description = what + " through a corporate brand-protection registrar, which usually means a "
                        + "defensive registration by the brand itself. Confirm it is held by the brand.";
            }
            default -> throw new IllegalArgumentException("not a low-risk disposition: " + candidate.disposition());
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("permutationType", candidate.permutationType());
        evidence.put("resolvedIps", candidate.resolvedIps());
        evidence.put("assessment", candidate.disposition().name());
        if (candidate.registrationDate() != null) {
            evidence.put("registrationDate", candidate.registrationDate().toString());
        }
        return new RawFinding(
                "TYPOSQUAT_DOMAIN_REGISTERED",
                severity,
                Category.BRAND,
                "Registered lookalike domain: " + candidate.domain(),
                description,
                candidate.domain(),
                evidence);
    }
}
