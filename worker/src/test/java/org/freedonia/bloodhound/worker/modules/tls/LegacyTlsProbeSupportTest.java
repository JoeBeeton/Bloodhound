package org.freedonia.bloodhound.worker.modules.tls;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class LegacyTlsProbeSupportTest {

    /** The real JDK 21 default, verbatim - the point is that only the two TLS entries go. */
    private static final String JDK21_DEFAULT = "SSLv3, TLSv1, TLSv1.1, DTLSv1.0, RC4, DES, MD5withRSA, "
            + "DH keySize < 1024, EC keySize < 224, 3DES_EDE_CBC, anon, NULL, ECDH";

    @Test
    void removesOnlyTls1AndTls11_leavingEveryOtherEntryIncludingDtls() {
        assertThat(LegacyTlsProbeSupport.withoutLegacyProtocols(JDK21_DEFAULT))
                .isEqualTo("SSLv3, DTLSv1.0, RC4, DES, MD5withRSA, DH keySize < 1024, EC keySize < 224, "
                        + "3DES_EDE_CBC, anon, NULL, ECDH");
    }

    /** The old scan-time regex turned "DTLSv1.0" into "D.0" - exact-entry matching must not. */
    @Test
    void dtlsEntryIsNotMangled() {
        assertThat(LegacyTlsProbeSupport.withoutLegacyProtocols("DTLSv1.0, TLSv1")).isEqualTo("DTLSv1.0");
    }

    @Test
    void nullOrBlankInput_yieldsEmpty() {
        assertThat(LegacyTlsProbeSupport.withoutLegacyProtocols(null)).isEmpty();
        assertThat(LegacyTlsProbeSupport.withoutLegacyProtocols("  ")).isEmpty();
    }

    @Test
    void alreadyRelaxedList_isUnchanged() {
        assertThat(LegacyTlsProbeSupport.withoutLegacyProtocols("SSLv3, RC4")).isEqualTo("SSLv3, RC4");
    }
}
