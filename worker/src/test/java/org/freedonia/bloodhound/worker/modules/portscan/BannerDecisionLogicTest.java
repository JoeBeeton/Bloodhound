package org.freedonia.bloodhound.worker.modules.portscan;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class BannerDecisionLogicTest {

    @Test
    void identifiesSshFromRealOpenSshBanner() {
        var guess = BannerDecisionLogic.fromBanner("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\nProtocol mismatch.\n");

        assertThat(guess.name()).isEqualTo("ssh");
        assertThat(guess.version()).isEqualTo("6.6.1p1");
    }

    @Test
    void identifiesFtpFrom220Banner() {
        var guess = BannerDecisionLogic.fromBanner("220 (vsFTPd 3.0.3)");

        assertThat(guess.name()).isEqualTo("ftp");
        assertThat(guess.product()).contains("vsFTPd 3.0.3");
    }

    @Test
    void identifiesSmtpFrom220Banner() {
        var guess = BannerDecisionLogic.fromBanner("220 mail.example.com ESMTP Postfix");

        assertThat(guess.name()).isEqualTo("smtp");
    }

    @Test
    void identifiesPop3FromOkBanner() {
        assertThat(BannerDecisionLogic.fromBanner("+OK POP3 ready").name()).isEqualTo("pop3");
    }

    @Test
    void identifiesImapFromOkBanner() {
        assertThat(BannerDecisionLogic.fromBanner("* OK IMAP4rev1 ready").name()).isEqualTo("imap");
    }

    @Test
    void unrecognizedBannerReportsRawTextWithoutGuessingName() {
        var guess = BannerDecisionLogic.fromBanner("some arbitrary text a service happened to send");

        assertThat(guess.name()).isNull();
        assertThat(guess.product()).isEqualTo("some arbitrary text a service happened to send");
    }

    @Test
    void emptyBannerYieldsNoGuessAtAll() {
        var guess = BannerDecisionLogic.fromBanner("   ");

        assertThat(guess.name()).isNull();
        assertThat(guess.product()).isNull();
    }

    @Test
    void splitsRealApacheServerHeader() {
        var guess = BannerDecisionLogic.fromHttpServerHeader("Apache/2.4.7 (Ubuntu)");

        assertThat(guess.name()).isEqualTo("http");
        assertThat(guess.product()).isEqualTo("Apache");
        assertThat(guess.version()).isEqualTo("2.4.7 (Ubuntu)");
    }

    @Test
    void splitsNginxServerHeader() {
        var guess = BannerDecisionLogic.fromHttpServerHeader("nginx/1.18.0");

        assertThat(guess.product()).isEqualTo("nginx");
        assertThat(guess.version()).isEqualTo("1.18.0");
    }

    @Test
    void serverHeaderWithNoVersionKeepsWholeValueAsProduct() {
        var guess = BannerDecisionLogic.fromHttpServerHeader("cloudflare");

        assertThat(guess.product()).isEqualTo("cloudflare");
        assertThat(guess.version()).isNull();
    }
}
