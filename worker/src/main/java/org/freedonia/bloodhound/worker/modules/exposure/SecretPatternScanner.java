package org.freedonia.bloodhound.worker.modules.exposure;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Greps an already-fetched file body (an exposed .env, .git/config, or AWS
 * credentials file - never a fresh fetch of its own) for live-looking secret
 * patterns, gitleaks-style. Purely regex-based on response bytes the fetcher
 * already downloaded for an unrelated exposure check, so this stays within
 * the Tier 1 passive boundary: no new network calls, no attempt to validate
 * whether a matched key is actually still active.
 *
 * <p>Hand-written rather than pulled from an existing signature database -
 * same reasoning as {@code TechDecisionLogic}'s fingerprints after the
 * Wappalyzer GPLv3 conflict: keep every pattern original, matched against
 * publicly documented credential formats rather than a third party's
 * curated list.
 *
 * <p>Matches are reported by pattern name and a redacted preview only - the
 * full matched string is never placed into a finding's evidence, since
 * findings are persisted (Postgres, UI, exports) and re-displaying a live
 * credential there would just create a second, Bloodhound-controlled place
 * for it to leak from.
 */
public final class SecretPatternScanner {

    public record Match(String patternName, String redactedPreview) {}

    private record NamedPattern(String name, Pattern pattern) {}

    /** Caps how many distinct pattern types get reported per file - this is a signal, not a full leak inventory. */
    private static final int MAX_MATCHES = 10;

    private static final List<NamedPattern> PATTERNS = List.of(
            new NamedPattern("AWS Access Key ID", Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b")),
            new NamedPattern(
                    "AWS Secret Access Key",
                    Pattern.compile("(?i)aws_secret_access_key\\s*=\\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
            new NamedPattern(
                    "Private Key Block",
                    Pattern.compile("-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
            new NamedPattern("Slack Token", Pattern.compile("xox[baprs]-[0-9A-Za-z-]{10,}")),
            new NamedPattern("Slack Webhook URL", Pattern.compile("hooks\\.slack\\.com/services/[A-Za-z0-9/]{20,}")),
            new NamedPattern("GitHub Token", Pattern.compile("gh[pousr]_[A-Za-z0-9]{36,}")),
            new NamedPattern("Stripe API Key", Pattern.compile("(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}")),
            new NamedPattern("Google API Key", Pattern.compile("AIza[0-9A-Za-z\\-_]{35}")),
            new NamedPattern(
                    "Credential-Embedded URL",
                    Pattern.compile("[a-zA-Z][a-zA-Z0-9+.-]*://[^\\s:/@'\"]+:[^\\s:/@'\"]+@[^\\s'\"]+")),
            new NamedPattern(
                    "Generic High-Entropy Secret Assignment",
                    Pattern.compile(
                            "(?i)(?:secret|token|api[_-]?key|password|passwd)\\b\\s*[:=]\\s*['\"][A-Za-z0-9/+_-]{20,}['\"]")));

    private SecretPatternScanner() {}

    public static List<Match> scan(String body) {
        if (body == null || body.isBlank()) {
            return List.of();
        }
        Set<String> seenNames = new LinkedHashSet<>();
        List<Match> matches = new ArrayList<>();
        for (NamedPattern np : PATTERNS) {
            if (matches.size() >= MAX_MATCHES) {
                break;
            }
            Matcher m = np.pattern().matcher(body);
            if (m.find() && seenNames.add(np.name())) {
                matches.add(new Match(np.name(), redact(m.group())));
            }
        }
        return matches;
    }

    static String redact(String raw) {
        if (raw.length() <= 8) {
            return "*".repeat(raw.length());
        }
        return raw.substring(0, 4) + "\u2026" + raw.substring(raw.length() - 4);
    }
}
