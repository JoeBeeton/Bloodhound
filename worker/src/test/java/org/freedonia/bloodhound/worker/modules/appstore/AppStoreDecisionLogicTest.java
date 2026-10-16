package org.freedonia.bloodhound.worker.modules.appstore;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.freedonia.bloodhound.common.findings.RawFinding;
import org.junit.jupiter.api.Test;

class AppStoreDecisionLogicTest {

    private static List<String> ruleIds(List<RawFinding> findings) {
        return findings.stream().map(RawFinding::ruleId).toList();
    }

    /** The real, live-found case this feature exists to catch. */
    @Test
    void titleMentionsBrand_developerDoesNot_flagged() {
        AppResult suspicious = new AppResult(
                "APPLE_APP_STORE", "6756574462", "JAJA Finance Tracker", "Linton Philip",
                "https://apps.apple.com/gb/app/id6756574462", 0.0, 0);

        List<RawFinding> findings = AppStoreDecisionLogic.decide("jaja.co.uk", "jaja", List.of(suspicious));

        assertThat(findings).hasSize(1);
        RawFinding finding = findings.get(0);
        assertThat(finding.ruleId()).isEqualTo("BRAND_IMPERSONATING_APP_DETECTED");
        assertThat(finding.severity().name()).isEqualTo("MEDIUM");
        assertThat(finding.affectedAsset()).isEqualTo("https://apps.apple.com/gb/app/id6756574462");
        assertThat(finding.evidence())
                .containsEntry("store", "APPLE_APP_STORE")
                .containsEntry("title", "JAJA Finance Tracker")
                .containsEntry("developer", "Linton Philip");
    }

    /** The real company's own apps - developer name itself contains the brand, correctly silent. */
    @Test
    void titleMentionsBrand_developerAlsoMentionsBrand_notFlagged() {
        AppResult legit = new AppResult(
                "APPLE_APP_STORE", "1515256908", "Jaja Credit Card", "Jaja Finance Ltd",
                "https://apps.apple.com/gb/app/id1515256908", 4.8, 22);

        assertThat(ruleIds(AppStoreDecisionLogic.decide("jaja.co.uk", "jaja", List.of(legit)))).isEmpty();
    }

    @Test
    void titleDoesNotMentionBrandAtAll_notFlagged() {
        AppResult unrelated = new AppResult(
                "APPLE_APP_STORE", "999", "Revolut — Banking & Beyond", "Revolut Ltd",
                "https://apps.apple.com/gb/app/id999", 4.7, 50000);

        assertThat(ruleIds(AppStoreDecisionLogic.decide("jaja.co.uk", "jaja", List.of(unrelated)))).isEmpty();
    }

    @Test
    void matchingIsCaseInsensitive() {
        AppResult suspicious = new AppResult(
                "GOOGLE_PLAY", "com.example.jajatracker", "jaja Finance Tracker", "Some Developer",
                "https://play.google.com/store/apps/details?id=com.example.jajatracker", null, null);

        assertThat(ruleIds(AppStoreDecisionLogic.decide("jaja.co.uk", "JAJA", List.of(suspicious))))
                .contains("BRAND_IMPERSONATING_APP_DETECTED");
    }

    @Test
    void nullDeveloper_treatedAsNotMatchingBrand_flagged() {
        AppResult result = new AppResult(
                "GOOGLE_PLAY", "com.example.jaja", "Jaja Wallet", null,
                "https://play.google.com/store/apps/details?id=com.example.jaja", null, null);

        List<RawFinding> findings = AppStoreDecisionLogic.decide("jaja.co.uk", "jaja", List.of(result));
        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).evidence()).containsEntry("developer", "");
    }

    @Test
    void nullTitle_skippedRatherThanThrowing() {
        AppResult result = new AppResult("GOOGLE_PLAY", "com.example.x", null, "Some Dev", null, null, null);
        assertThat(AppStoreDecisionLogic.decide("jaja.co.uk", "jaja", List.of(result))).isEmpty();
    }

    @Test
    void googlePlayStoreLabel_usedInDescription() {
        AppResult result = new AppResult(
                "GOOGLE_PLAY", "com.example.jaja", "Jaja Pro", "Unrelated Dev",
                "https://play.google.com/store/apps/details?id=com.example.jaja", null, null);

        RawFinding finding = AppStoreDecisionLogic.decide("jaja.co.uk", "jaja", List.of(result)).get(0);
        assertThat(finding.description()).contains("Google Play");
    }

    @Test
    void emptyResultList_noFindings() {
        assertThat(AppStoreDecisionLogic.decide("jaja.co.uk", "jaja", List.of())).isEmpty();
    }
}
