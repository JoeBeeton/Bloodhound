package org.freedonia.bloodhound.server.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

/**
 * A security review found ChangePasswordRequest (the one place in this app a human actually
 * chooses their own password - admin-created and SCIM-provisioned accounts get a random
 * SecureRandom-generated temporary password instead, never user-chosen) validated only length
 * (@Size(min=8, max=200)), nothing else. NIST 800-63B's current guidance is explicit that
 * composition rules (require a digit, a symbol, etc.) are NOT recommended - they push users
 * toward predictable substitutions ("Password1!") without meaningfully raising real-world
 * guessability - but SHALL compare a chosen password against a list of values known to be
 * commonly used or otherwise compromised, and against context-specific values (the account's own
 * username/email). This implements exactly that narrower, evidence-based check rather than a
 * composition-rule requirement.
 *
 * <p>Bundled common-passwords.txt (~300 entries from widely-published "most common/worst
 * passwords" lists - keyboard-walk patterns, single dictionary words, trivial word+digit
 * combinations) rather than a live call to a breach-check API (e.g. HaveIBeenPwned's
 * k-anonymity Passwords API): this app is meant to be deployable fully offline/air-gapped, and a
 * password-change request - a security-critical path that must keep working regardless of
 * third-party network reachability - shouldn't gain an external dependency. The bundled list
 * intentionally isn't exhaustive; it's a floor against the most trivially guessable choices, not
 * a substitute for a real breach corpus.
 */
@Component
public class WeakPasswordChecker {

    private final Set<String> commonPasswords;

    public WeakPasswordChecker() {
        this.commonPasswords = loadCommonPasswords();
    }

    /**
     * True if the password is either a known common/weak value, or trivially derived from the
     * account's own email (the exact email, or its local-part before '@') - both checked
     * case-insensitively, since an attacker guessing "Password1" will just as readily try
     * "password1".
     */
    public boolean isWeak(String password, String email) {
        String normalized = password.toLowerCase(Locale.ROOT);
        if (commonPasswords.contains(normalized)) {
            return true;
        }
        if (email == null || email.isBlank()) {
            return false;
        }
        String normalizedEmail = email.toLowerCase(Locale.ROOT);
        if (normalized.equals(normalizedEmail)) {
            return true;
        }
        int at = normalizedEmail.indexOf('@');
        String localPart = at < 0 ? normalizedEmail : normalizedEmail.substring(0, at);
        return !localPart.isBlank() && normalized.equals(localPart);
    }

    private static Set<String> loadCommonPasswords() {
        Set<String> values = new HashSet<>();
        ClassPathResource resource = new ClassPathResource("common-passwords.txt");
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(resource.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty()) {
                    values.add(trimmed.toLowerCase(Locale.ROOT));
                }
            }
        } catch (IOException e) {
            // The bundled resource is packaged with the jar, not user-supplied - a failure here
            // means a broken build, not a runtime condition worth degrading gracefully for.
            throw new UncheckedIOException("failed to load common-passwords.txt", e);
        }
        return Set.copyOf(values);
    }
}
