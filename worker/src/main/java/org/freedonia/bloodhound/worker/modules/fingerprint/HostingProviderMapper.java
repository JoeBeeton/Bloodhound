package org.freedonia.bloodhound.worker.modules.fingerprint;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Maps a raw ASN organization string (e.g. "AMAZON-02, US", "HETZNER-AS, DE")
 * to a friendly hosting-provider name. A bounded, curated substring table
 * covering the major providers - falls back to returning the raw string
 * unchanged so an unrecognized/smaller provider still shows real data rather
 * than being omitted.
 */
public final class HostingProviderMapper {

    private HostingProviderMapper() {}

    // Order matters where one pattern could be a substring of another's raw
    // org string - checked top to bottom, first match wins.
    private static final Map<String, String> PATTERNS = new LinkedHashMap<>();

    static {
        PATTERNS.put("digitalocean", "DigitalOcean");
        PATTERNS.put("hetzner", "Hetzner Online GmbH");
        PATTERNS.put("amazon", "Amazon Web Services");
        PATTERNS.put("google", "Google Cloud");
        PATTERNS.put("microsoft", "Microsoft Azure");
        PATTERNS.put("cloudflare", "Cloudflare");
        PATTERNS.put("ovh", "OVHcloud");
        PATTERNS.put("akamai", "Akamai / Linode");
        PATTERNS.put("linode", "Akamai / Linode");
        PATTERNS.put("fastly", "Fastly");
        PATTERNS.put("godaddy", "GoDaddy");
        PATTERNS.put("namecheap", "Namecheap");
        PATTERNS.put("oracle", "Oracle Cloud");
        PATTERNS.put("ibm", "IBM Cloud");
        PATTERNS.put("vultr", "Vultr");
        PATTERNS.put("rackspace", "Rackspace");
        PATTERNS.put("cloudflarenet", "Cloudflare");
    }

    /** Returns a friendly provider name if recognized, otherwise the raw org string unchanged (or null if the input itself is null/blank). */
    public static String toFriendlyName(String rawAsnOrg) {
        if (rawAsnOrg == null || rawAsnOrg.isBlank()) {
            return null;
        }
        String lower = rawAsnOrg.toLowerCase(Locale.ROOT);
        for (Map.Entry<String, String> entry : PATTERNS.entrySet()) {
            if (lower.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        return rawAsnOrg;
    }
}
