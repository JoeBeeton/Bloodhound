package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class SshAlgorithmDecisionLogicTest {

    private static Zgrab2JsonParser.SshAlgorithms algorithms(
            List<String> kex, List<String> hostKey, List<String> ciphers, List<String> macs) {
        return new Zgrab2JsonParser.SshAlgorithms(kex, hostKey, ciphers, macs);
    }

    @Test
    void modernConfig_realGithubShape_nothingFlagged() {
        var result = SshAlgorithmDecisionLogic.findWeak(algorithms(
                List.of("curve25519-sha256", "diffie-hellman-group-exchange-sha256"),
                List.of("ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"),
                List.of("chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"),
                List.of("hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com")));

        assertThat(result.isEmpty()).isTrue();
    }

    @Test
    void weakKexAlgorithm_flagged() {
        var result = SshAlgorithmDecisionLogic.findWeak(
                algorithms(List.of("diffie-hellman-group1-sha1", "curve25519-sha256"), List.of(), List.of(), List.of()));

        assertThat(result.kex()).containsExactly("diffie-hellman-group1-sha1");
        assertThat(result.isEmpty()).isFalse();
    }

    /** diffie-hellman-group14-sha256 (the modern replacement) must NOT be caught by a loose "group14" substring match. */
    @Test
    void modernGroup14Sha256Kex_notFlagged() {
        var result = SshAlgorithmDecisionLogic.findWeak(
                algorithms(List.of("diffie-hellman-group14-sha256"), List.of(), List.of(), List.of()));

        assertThat(result.kex()).isEmpty();
    }

    @Test
    void weakHostKeyAlgorithms_flagged() {
        var result =
                SshAlgorithmDecisionLogic.findWeak(algorithms(List.of(), List.of("ssh-rsa", "ssh-dss"), List.of(), List.of()));

        assertThat(result.hostKey()).containsExactlyInAnyOrder("ssh-rsa", "ssh-dss");
    }

    /** rsa-sha2-512/256 (the modern SHA-2 replacements for ssh-rsa) must NOT be caught by a loose "rsa" substring match. */
    @Test
    void modernRsaSha2HostKeyAlgorithms_notFlagged() {
        var result = SshAlgorithmDecisionLogic.findWeak(
                algorithms(List.of(), List.of("rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519"), List.of(), List.of()));

        assertThat(result.hostKey()).isEmpty();
    }

    @Test
    void cbcCipher_flagged() {
        var result = SshAlgorithmDecisionLogic.findWeak(
                algorithms(List.of(), List.of(), List.of("aes128-cbc", "aes256-ctr"), List.of()));

        assertThat(result.ciphers()).containsExactly("aes128-cbc");
    }

    @Test
    void arcfourCipher_flagged() {
        var result = SshAlgorithmDecisionLogic.findWeak(algorithms(List.of(), List.of(), List.of("arcfour256"), List.of()));

        assertThat(result.ciphers()).containsExactly("arcfour256");
    }

    @Test
    void md5Mac_flagged() {
        var result = SshAlgorithmDecisionLogic.findWeak(
                algorithms(List.of(), List.of(), List.of(), List.of("hmac-md5", "hmac-sha2-256")));

        assertThat(result.macs()).containsExactly("hmac-md5");
    }

    @Test
    void truncatedSha1Mac_flagged() {
        var result =
                SshAlgorithmDecisionLogic.findWeak(algorithms(List.of(), List.of(), List.of(), List.of("hmac-sha1-96")));

        assertThat(result.macs()).containsExactly("hmac-sha1-96");
    }

    @Test
    void emptyEverything_isEmptyTrue() {
        assertThat(SshAlgorithmDecisionLogic.findWeak(algorithms(List.of(), List.of(), List.of(), List.of())).isEmpty())
                .isTrue();
    }
}
