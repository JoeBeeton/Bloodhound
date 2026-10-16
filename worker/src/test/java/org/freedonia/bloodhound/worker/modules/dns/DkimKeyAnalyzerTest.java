package org.freedonia.bloodhound.worker.modules.dns;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class DkimKeyAnalyzerTest {

    @Test
    void realGithubComKey_2048bits() {
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength(DnsPostureParserTest.STRONG_DKIM_TXT)).hasValue(2048);
    }

    @Test
    void realMicrosoftKey_1024bits() {
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength(DnsPostureParserTest.WEAK_DKIM_TXT)).hasValue(1024);
    }

    @Test
    void explicitKRsaTag_stillParsed() {
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength("v=DKIM1; k=rsa; p=" + rawP(DnsPostureParserTest.STRONG_DKIM_TXT)))
                .hasValue(2048);
    }

    @Test
    void ed25519Key_notEvaluated_differentKeyTypeNotWeakRsa() {
        // ed25519 DKIM keys are a fixed 256 bits by design and inherently strong - not a candidate
        // for this RSA-specific weak-key check at all, so this must return empty, not "256 < 2048".
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength("v=DKIM1; k=ed25519; p=MC4CAQAwBQYDK2VwBCIEIBG1pCQ0QwRs")).isEmpty();
    }

    @Test
    void revokedKey_emptyPTag_notFlaggedAsWeak() {
        // RFC 6376 3.6.1: an empty p= means "this key is revoked", a different condition entirely
        // from "weak but live" - must not be treated as a 0-bit key or any other kind of weak key.
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength("v=DKIM1; k=rsa; p=")).isEmpty();
    }

    @Test
    void malformedBase64_noCrash_returnsEmpty() {
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength("v=DKIM1; k=rsa; p=not-valid-base64!!!")).isEmpty();
    }

    @Test
    void missingPTag_returnsEmpty() {
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength("v=DKIM1; k=rsa")).isEmpty();
    }

    @Test
    void nullValue_returnsEmpty() {
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength(null)).isEmpty();
    }

    @Test
    void noKTagAtAll_defaultsToRsaPerRfc6376_stillParsed() {
        // RFC 6376 3.6.1: k= defaults to "rsa" when absent - a real-world DKIM record commonly
        // omits it entirely rather than spelling out the default.
        assertThat(DkimKeyAnalyzer.rsaKeyBitLength("v=DKIM1; p=" + rawP(DnsPostureParserTest.WEAK_DKIM_TXT)))
                .hasValue(1024);
    }

    private static String rawP(String dkimTxt) {
        int idx = dkimTxt.indexOf("p=");
        return dkimTxt.substring(idx + 2);
    }
}
