package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure interpretation of raw banner text / HTTP Server headers into a
 * best-effort service identification - no process/JSON work here, fully
 * unit-testable. Deliberately narrow and hand-written rather than an
 * imported signature database - reusing another scanner's own proprietary
 * probe/fingerprint data here would just trade one licensing problem for
 * another. This covers the common, self-announcing cases only; anything
 * else is reported with the raw banner text as evidence and no name/version
 * guess, which is honest rather than fabricated precision.
 */
public final class BannerDecisionLogic {

    public record ServiceGuess(String name, String product, String version) {}

    private static final Pattern OPENSSH_VERSION = Pattern.compile("OpenSSH_([\\w.]+)");
    private static final Pattern SERVER_HEADER = Pattern.compile("^([^/\\s]+)(?:/(\\S+))?(.*)$");

    private BannerDecisionLogic() {}

    public static ServiceGuess fromBanner(String banner) {
        String trimmed = banner.strip();
        if (trimmed.isEmpty()) {
            return new ServiceGuess(null, null, null);
        }
        if (trimmed.startsWith("SSH-")) {
            Matcher m = OPENSSH_VERSION.matcher(trimmed);
            return new ServiceGuess("ssh", trimmed, m.find() ? m.group(1) : null);
        }
        if (trimmed.startsWith("220")) {
            String upper = trimmed.toUpperCase();
            if (upper.contains("FTP")) {
                return new ServiceGuess("ftp", trimmed, null);
            }
            if (upper.contains("SMTP") || upper.contains("ESMTP")) {
                return new ServiceGuess("smtp", trimmed, null);
            }
            return new ServiceGuess(null, trimmed, null);
        }
        if (trimmed.startsWith("+OK")) {
            return new ServiceGuess("pop3", trimmed, null);
        }
        if (trimmed.startsWith("* OK")) {
            return new ServiceGuess("imap", trimmed, null);
        }
        return new ServiceGuess(null, trimmed, null);
    }

    /** e.g. "Apache/2.4.7 (Ubuntu)" -&gt; product="Apache", version="2.4.7 (Ubuntu)". */
    public static ServiceGuess fromHttpServerHeader(String serverHeader) {
        String trimmed = serverHeader.strip();
        Matcher m = SERVER_HEADER.matcher(trimmed);
        if (m.matches() && m.group(2) != null) {
            String version = (m.group(2) + m.group(3)).strip();
            return new ServiceGuess("http", m.group(1), version.isEmpty() ? null : version);
        }
        return new ServiceGuess("http", trimmed, null);
    }
}
