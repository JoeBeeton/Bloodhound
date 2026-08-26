package org.freedonia.bloodhound.worker.modules.typosquat;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Generates typosquat/lookalike-domain candidates for a root domain, covering
 * the standard technique categories (the same taxonomy the open-source
 * dnstwist tool uses as its reference - this is an independent
 * implementation, not a dependency on that tool). Deliberately ASCII-only:
 * full Unicode homoglyph/IDN-homograph generation (real punycode lookalikes)
 * is a materially larger, messier problem, explicitly out of scope here.
 *
 * <p>Domain splitting is a simple last-dot split (label + tld) - the same
 * simplification {@code WhoisFetcher.tldOf()} already uses elsewhere in this
 * codebase. A full public-suffix-list-aware split (to correctly handle
 * multi-part TLDs like co.uk) is a known limitation, not solved here.
 *
 * <p>Techniques are added in an order that puts the small, high-confidence
 * categories (TLD swap, homoglyph) first and the length-scaling ones
 * (adjacent-key substitution is the largest - roughly 4 variants per
 * character) last, so if a long domain name pushes past {@link
 * #MAX_CANDIDATES} it's the bulkiest category that gets truncated, not the
 * classic, highest-signal ones.
 */
public final class PermutationGenerator {

    public record Candidate(String domain, String permutationType) {}

    /** Bounds total output regardless of label length - keeps DNS-checking work per scan predictable. */
    private static final int MAX_CANDIDATES = 100;

    private static final List<String> GENERIC_TLD_SWAPS = List.of("net", "org", "co", "io", "info", "biz");
    /** ".com"-specific tricks: dropping a single letter from "com" yields these two real, commonly-abused TLDs. */
    private static final List<String> COM_SPECIFIC_TLD_SWAPS = List.of("cm", "om");

    // Small, high-confidence ASCII-only confusable substitutions, applied once per occurrence in the label.
    private static final List<String[]> HOMOGLYPHS = List.of(
            new String[] {"o", "0"},
            new String[] {"0", "o"},
            new String[] {"l", "1"},
            new String[] {"i", "1"},
            new String[] {"s", "5"},
            new String[] {"e", "3"},
            new String[] {"a", "4"},
            new String[] {"m", "rn"});

    private static final Map<Character, String> QWERTY_ADJACENT = buildQwertyAdjacency();

    private PermutationGenerator() {}

    public static List<Candidate> generate(String rootDomain) {
        int lastDot = rootDomain == null ? -1 : rootDomain.lastIndexOf('.');
        if (lastDot <= 0 || lastDot == rootDomain.length() - 1) {
            return List.of();
        }
        String label = rootDomain.substring(0, lastDot).toLowerCase(Locale.ROOT);
        String tld = rootDomain.substring(lastDot + 1).toLowerCase(Locale.ROOT);

        // domain -> first-assigned permutation type. LinkedHashMap for determinism, and putIfAbsent
        // gives a stable pick on the rare occasion two techniques generate the same string.
        Map<String, String> byDomain = new LinkedHashMap<>();

        addTldSwaps(label, tld, byDomain);
        addHomoglyphs(label, tld, byDomain);
        addOmissions(label, tld, byDomain);
        addDuplications(label, tld, byDomain);
        addTranspositions(label, tld, byDomain);
        addHyphenations(label, tld, byDomain);
        addAdjacentKeySubstitutions(label, tld, byDomain);

        byDomain.remove(rootDomain.toLowerCase(Locale.ROOT));

        List<Candidate> result = new ArrayList<>();
        for (Map.Entry<String, String> entry : byDomain.entrySet()) {
            if (result.size() >= MAX_CANDIDATES) {
                break;
            }
            result.add(new Candidate(entry.getKey(), entry.getValue()));
        }
        return result;
    }

    private static void addOmissions(String label, String tld, Map<String, String> out) {
        for (int i = 0; i < label.length(); i++) {
            String variant = label.substring(0, i) + label.substring(i + 1);
            if (!variant.isEmpty()) {
                put(out, variant + "." + tld, "OMISSION");
            }
        }
    }

    private static void addDuplications(String label, String tld, Map<String, String> out) {
        for (int i = 0; i < label.length(); i++) {
            String variant = label.substring(0, i + 1) + label.charAt(i) + label.substring(i + 1);
            put(out, variant + "." + tld, "DUPLICATION");
        }
    }

    private static void addTranspositions(String label, String tld, Map<String, String> out) {
        for (int i = 0; i < label.length() - 1; i++) {
            char[] chars = label.toCharArray();
            char tmp = chars[i];
            chars[i] = chars[i + 1];
            chars[i + 1] = tmp;
            put(out, new String(chars) + "." + tld, "TRANSPOSITION");
        }
    }

    private static void addAdjacentKeySubstitutions(String label, String tld, Map<String, String> out) {
        for (int i = 0; i < label.length(); i++) {
            String adjacent = QWERTY_ADJACENT.get(label.charAt(i));
            if (adjacent == null) {
                continue;
            }
            for (char replacement : adjacent.toCharArray()) {
                String variant = label.substring(0, i) + replacement + label.substring(i + 1);
                put(out, variant + "." + tld, "ADJACENT_KEY_SUBSTITUTION");
            }
        }
    }

    private static void addHomoglyphs(String label, String tld, Map<String, String> out) {
        for (String[] pair : HOMOGLYPHS) {
            String from = pair[0];
            String to = pair[1];
            int idx = label.indexOf(from);
            while (idx >= 0) {
                String variant = label.substring(0, idx) + to + label.substring(idx + from.length());
                put(out, variant + "." + tld, "HOMOGLYPH");
                idx = label.indexOf(from, idx + 1);
            }
        }
    }

    private static void addHyphenations(String label, String tld, Map<String, String> out) {
        for (int i = 1; i < label.length(); i++) {
            String variant = label.substring(0, i) + "-" + label.substring(i);
            put(out, variant + "." + tld, "HYPHENATION");
        }
    }

    private static void addTldSwaps(String label, String tld, Map<String, String> out) {
        for (String swap : GENERIC_TLD_SWAPS) {
            if (!swap.equals(tld)) {
                put(out, label + "." + swap, "TLD_SWAP");
            }
        }
        if ("com".equals(tld)) {
            for (String swap : COM_SPECIFIC_TLD_SWAPS) {
                put(out, label + "." + swap, "TLD_SWAP");
            }
        }
    }

    private static void put(Map<String, String> out, String domain, String type) {
        out.putIfAbsent(domain, type);
    }

    private static Map<Character, String> buildQwertyAdjacency() {
        Map<Character, String> m = new HashMap<>();
        m.put('q', "wa");
        m.put('w', "qeas");
        m.put('e', "wrsd");
        m.put('r', "etdf");
        m.put('t', "ryfg");
        m.put('y', "tugh");
        m.put('u', "yihj");
        m.put('i', "uojk");
        m.put('o', "ipkl");
        m.put('p', "ol");
        m.put('a', "qwsz");
        m.put('s', "awedxz");
        m.put('d', "serfcx");
        m.put('f', "drtgvc");
        m.put('g', "ftyhbv");
        m.put('h', "gyujnb");
        m.put('j', "huikmn");
        m.put('k', "jiolm");
        m.put('l', "kop");
        m.put('z', "asx");
        m.put('x', "zsdc");
        m.put('c', "xdfv");
        m.put('v', "cfgb");
        m.put('b', "vghn");
        m.put('n', "bhjm");
        m.put('m', "njk");
        return m;
    }
}
