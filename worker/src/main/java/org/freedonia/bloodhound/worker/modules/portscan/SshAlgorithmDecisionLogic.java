package org.freedonia.bloodhound.worker.modules.portscan;

import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Pure classification of an SSH server's offered algorithm lists against known-weak markers - the
 * same "server's own offer is the signal, not what our client happened to pick" reasoning
 * {@code WeakCipherProbe}/{@code TlsDecisionLogic} already use for TLS, applied to SSH. Closes a
 * gap found comparing this product's rule catalog against ssh-audit/Mozilla's OpenSSH hardening
 * guide conventions: no SSH protocol-level configuration check existed here before (only a banner
 * version grab, which says nothing about negotiable algorithms).
 *
 * <p>KEX/host-key markers are exact-name matches, not substrings: several modern, safe algorithm
 * names contain substrings of weak ones (e.g. "rsa-sha2-512" contains "rsa", "diffie-hellman-
 * group14-sha256" contains "diffie-hellman-group14") - a loose substring match would wrongly flag
 * them. Cipher/MAC markers are safe as substrings since no modern algorithm name happens to contain
 * "cbc"/"arcfour"/"md5".
 */
public final class SshAlgorithmDecisionLogic {

    /** CVE-2002-20001-class (1024-bit, Logjam-adjacent) and SHA-1-based KEX - diffie-hellman-group14-sha256 and the curve/ECDH-based algorithms are NOT included, as they remain secure. */
    private static final Set<String> WEAK_KEX = Set.of(
            "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1");

    /** ssh-rsa's SHA-1-based signature and ssh-dss's 1024-bit DSA key are both deprecated by OpenSSH itself (disabled by default since 8.8) - rsa-sha2-256/512 are the safe SHA-2 replacements and are NOT included. */
    private static final Set<String> WEAK_HOST_KEY = Set.of("ssh-rsa", "ssh-dss");

    private static final List<String> WEAK_CIPHER_MARKERS = List.of("cbc", "arcfour", "none");

    private static final List<String> WEAK_MAC_MARKERS = List.of("md5", "sha1-96");

    private SshAlgorithmDecisionLogic() {}

    public record WeakAlgorithms(List<String> kex, List<String> hostKey, List<String> ciphers, List<String> macs) {
        public boolean isEmpty() {
            return kex.isEmpty() && hostKey.isEmpty() && ciphers.isEmpty() && macs.isEmpty();
        }
    }

    public static WeakAlgorithms findWeak(Zgrab2JsonParser.SshAlgorithms algorithms) {
        return new WeakAlgorithms(
                algorithms.kexAlgorithms().stream().filter(WEAK_KEX::contains).toList(),
                algorithms.hostKeyAlgorithms().stream().filter(WEAK_HOST_KEY::contains).toList(),
                algorithms.ciphers().stream().filter(c -> containsAnyMarker(c, WEAK_CIPHER_MARKERS)).toList(),
                algorithms.macs().stream().filter(m -> containsAnyMarker(m, WEAK_MAC_MARKERS)).toList());
    }

    private static boolean containsAnyMarker(String value, List<String> markers) {
        String lower = value.toLowerCase(Locale.ROOT);
        return markers.stream().anyMatch(lower::contains);
    }
}
