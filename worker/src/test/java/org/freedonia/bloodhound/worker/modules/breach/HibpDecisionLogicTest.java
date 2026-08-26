package org.freedonia.bloodhound.worker.modules.breach;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class HibpDecisionLogicTest {

    @Test
    void domainSearch_realWorldMultiAliasResponse_unionsUniqueBreachNames() {
        // Shape confirmed against HIBP's own published API docs.
        String body = """
                {"alias1":["Adobe"],"alias2":["Adobe","Gawker","Stratfor"]}
                """;
        Set<String> names = assertParsesTo(200, body);
        assertThat(names).containsExactlyInAnyOrder("Adobe", "Gawker", "Stratfor");
    }

    @Test
    void domainSearch_emptyObject_noBreaches() {
        assertThat(assertParsesTo(200, "{}")).isEmpty();
    }

    @Test
    void domainSearch_403_treatedAsNoDataNotError() throws Exception {
        // 403 is HIBP's documented response for a domain that isn't verified under the
        // calling API key's account - an expected, common state, not a failure.
        assertThat(HibpDecisionLogic.parseDomainSearchBreachNames(403, "{\"message\":\"forbidden\"}")).isEmpty();
    }

    @Test
    void domainSearch_404_treatedAsNoDataDefensively() throws Exception {
        assertThat(HibpDecisionLogic.parseDomainSearchBreachNames(404, null)).isEmpty();
    }

    @Test
    void domainSearch_429RateLimited_throwsRatherThanSilentlyEmpty() {
        // Unlike 403/404, a rate-limit or server error is a real failure the caller
        // should surface (and let the job retry/backoff machinery handle), not something
        // that should silently look identical to "no breaches found".
        assertThatThrownBy(() -> HibpDecisionLogic.parseDomainSearchBreachNames(429, null))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void domainSearch_5xx_throws() {
        assertThatThrownBy(() -> HibpDecisionLogic.parseDomainSearchBreachNames(500, null))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void domainSearch_blankBodyWith200_noBreaches() throws Exception {
        assertThat(HibpDecisionLogic.parseDomainSearchBreachNames(200, "")).isEmpty();
        assertThat(HibpDecisionLogic.parseDomainSearchBreachNames(200, null)).isEmpty();
    }

    @Test
    void breachDetail_realWorldAdobeResponse_parsesDescriptionAndDate() {
        // Shape confirmed against HIBP's own published API docs.
        String body = """
                {"Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04",
                "AddedDate":"2013-12-04T00:00Z","Description":"In October 2013, 153 million Adobe accounts were breached.",
                "PwnCount":152445165,"IsVerified":true}
                """;
        Optional<HibpDecisionLogic.BreachDetail> detail = HibpDecisionLogic.parseBreachDetail(200, body);

        assertThat(detail).isPresent();
        assertThat(detail.get().description()).isEqualTo("In October 2013, 153 million Adobe accounts were breached.");
        assertThat(detail.get().breachDate()).isEqualTo(Instant.parse("2013-10-04T00:00:00Z"));
    }

    @Test
    void breachDetail_404UnknownBreachName_empty() {
        assertThat(HibpDecisionLogic.parseBreachDetail(404, null)).isEmpty();
    }

    @Test
    void breachDetail_malformedJson_emptyRatherThanThrowing() {
        assertThat(HibpDecisionLogic.parseBreachDetail(200, "not json")).isEmpty();
    }

    @Test
    void breachDetail_missingBreachDateField_stillReturnsDescriptionWithNullDate() {
        Optional<HibpDecisionLogic.BreachDetail> detail =
                HibpDecisionLogic.parseBreachDetail(200, "{\"Description\":\"Some breach\"}");

        assertThat(detail).isPresent();
        assertThat(detail.get().description()).isEqualTo("Some breach");
        assertThat(detail.get().breachDate()).isNull();
    }

    private static Set<String> assertParsesTo(int status, String body) {
        try {
            return HibpDecisionLogic.parseDomainSearchBreachNames(status, body);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }
}
