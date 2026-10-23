package org.freedonia.bloodhound.worker.modules;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * A security review found Nuclei's {@code extracted-results}/{@code curl-command} and ZAP's
 * {@code evidence}/{@code param} were copied into a finding's evidence unchanged, unlike every
 * first-party rule that extracts a secret (see {@code SecretPatternScanner}, which redacts).
 * Exposure templates are deliberately written to pull out tokens, keys, and file snippets - those
 * strings then get stored (Postgres, the UI, CSV export) and shown to every role that can read
 * findings, API keys included.
 *
 * <p>Unlike {@code SecretPatternScanner.redact} (a fixed first-4/last-4 collapse, used only after
 * that class's own regex has already confirmed *what kind* of secret it found), there is no such
 * confirmation here - this is opaque third-party tool output that might contain a live credential
 * anywhere in the string, not necessarily where a fixed-length preview would show it. Showing any
 * literal substring risks showing exactly the part that matters, so this keeps none at all: a
 * SHA-256 hash (lets an operator with independent access to raw worker/nuclei/zap logs correlate
 * a finding back to exactly what was captured, without this app being a second place the value
 * itself is stored in retrievable form) plus the original length (a real, if coarse, triage
 * signal - "nothing was extracted" reads differently from "200 characters were").
 */
public final class EvidenceRedaction {

    private EvidenceRedaction() {}

    public static String redact(String raw) {
        if (raw == null || raw.isBlank()) {
            return raw;
        }
        return "[redacted, " + raw.length() + " chars, sha256:" + sha256Hex(raw) + "]";
    }

    public static List<String> redactAll(List<String> raw) {
        return raw.stream().map(EvidenceRedaction::redact).toList();
    }

    private static String sha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is a mandatory JDK algorithm (JCA standard algorithm name) - unreachable.
            throw new IllegalStateException(e);
        }
    }
}
