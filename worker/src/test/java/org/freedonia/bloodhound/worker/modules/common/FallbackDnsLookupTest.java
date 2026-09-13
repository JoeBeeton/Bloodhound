package org.freedonia.bloodhound.worker.modules.common;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.Lookup;

class FallbackDnsLookupTest {

    /**
     * The whole point of the helper: a resolver that answered - even "no such name" - is a
     * definitive result, while a network error or timeout is not, and must never be read as "the
     * record is absent" (that reading is what made every DNS-posture rule fire on domains that
     * publish everything).
     */
    @Test
    void realAnswersIncludingNegativeOnes_areDefinitive() {
        assertThat(FallbackDnsLookup.isDefinitive(Lookup.SUCCESSFUL)).isTrue();
        assertThat(FallbackDnsLookup.isDefinitive(Lookup.HOST_NOT_FOUND)).isTrue();
        assertThat(FallbackDnsLookup.isDefinitive(Lookup.TYPE_NOT_FOUND)).isTrue();
    }

    @Test
    void resolverFailures_areNotDefinitive() {
        assertThat(FallbackDnsLookup.isDefinitive(Lookup.UNRECOVERABLE)).isFalse();
        assertThat(FallbackDnsLookup.isDefinitive(Lookup.TRY_AGAIN)).isFalse();
    }

    @Test
    void failedAnswer_isEmptyAndUnanswered() {
        assertThat(FallbackDnsLookup.Answer.FAILED.answered()).isFalse();
        assertThat(FallbackDnsLookup.Answer.FAILED.isEmpty()).isTrue();
    }
}
