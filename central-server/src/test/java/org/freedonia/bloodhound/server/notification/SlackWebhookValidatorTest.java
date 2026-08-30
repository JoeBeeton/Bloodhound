package org.freedonia.bloodhound.server.notification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SlackWebhookValidatorTest {

    @Test
    void acceptsGenuineSlackWebhookUrl() {
        // Deliberately not shaped like a real Slack webhook token (GitHub's secret
        // scanner blocks pushes containing anything that matches that pattern,
        // fake or not) - SlackWebhookValidator only checks scheme/host/path prefix
        // anyway, never the token itself, so this proves the same thing.
        assertTrue(SlackWebhookValidator.isValid("https://hooks.slack.com/services/not-a-real-token"));
    }

    @Test
    void rejectsNull() {
        assertFalse(SlackWebhookValidator.isValid(null));
    }

    @Test
    void rejectsBlank() {
        assertFalse(SlackWebhookValidator.isValid("   "));
    }

    @Test
    void rejectsNonSlackHost() {
        assertFalse(SlackWebhookValidator.isValid("https://evil.com/services/x/y/z"));
    }

    @Test
    void rejectsPlainHttp() {
        assertFalse(SlackWebhookValidator.isValid("http://hooks.slack.com/services/x/y/z"));
    }

    @Test
    void rejectsSubdomainConfusionSuffixTrick() {
        // "hooks.slack.com.evil.com" is a different, attacker-controlled host - getHost()
        // must not be treated as a prefix/contains match against the real host.
        assertFalse(SlackWebhookValidator.isValid("https://hooks.slack.com.evil.com/services/x/y/z"));
    }

    @Test
    void rejectsPathConfusionTrick() {
        // "hooks.slack.com" appearing as a path segment of a different host.
        assertFalse(SlackWebhookValidator.isValid("https://evil.com/hooks.slack.com/services/x/y/z"));
    }

    @Test
    void rejectsUserinfoConfusionTrick() {
        // Under RFC 3986 the host here is "evil.com" - URI#getHost() strips userinfo
        // correctly, which a naive string .contains("hooks.slack.com") check would not.
        assertFalse(SlackWebhookValidator.isValid("https://hooks.slack.com@evil.com/services/x/y/z"));
    }

    @Test
    void rejectsMissingServicesPath() {
        assertFalse(SlackWebhookValidator.isValid("https://hooks.slack.com/some-other-path"));
    }

    @Test
    void rejectsMalformedUri() {
        assertFalse(SlackWebhookValidator.isValid("not a url at all ::: %%"));
    }

    @Test
    void mask_realShapedUrl_keepsTeamAndWebhookIdRedactsSecret() {
        // Segments 1-2 (team + webhook id) are effectively identifiers, not secrets - the actual
        // bearer credential is the final segment, which must never come back from the mask.
        String masked = SlackWebhookValidator.mask("https://hooks.slack.com/services/T0123ABCD/B0456EFGH/xXxSecretTokenxXx");

        assertThat(masked).isEqualTo("https://hooks.slack.com/services/T0123ABCD/B0456EFGH/••••••••");
        assertThat(masked).doesNotContain("xXxSecretTokenxXx");
    }

    @Test
    void mask_null_returnsNull() {
        assertThat(SlackWebhookValidator.mask(null)).isNull();
    }

    @Test
    void mask_unexpectedShape_fallsBackToFullyRedacted_neverThrows() {
        assertThat(SlackWebhookValidator.mask("https://hooks.slack.com/services/not-a-real-token"))
                .isEqualTo("https://hooks.slack.com/services/••••••••");
    }

    @Test
    void mask_malformedUri_fallsBackToFullyRedacted_neverThrows() {
        assertThat(SlackWebhookValidator.mask("not a url at all ::: %%"))
                .isEqualTo("https://hooks.slack.com/services/••••••••");
    }
}
