package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class DanglingCnameDecisionLogicTest {

    private void assertTruePositive(String cname, String expectedService, String fingerprint) {
        Optional<DanglingCnameDecisionLogic.TakeoverService> match = DanglingCnameDecisionLogic.matchProvider(cname);
        assertThat(match).isPresent();
        assertThat(match.get().serviceName()).isEqualTo(expectedService);
        assertThat(DanglingCnameDecisionLogic.isUnclaimed(match.get(), "... " + fingerprint + " ...")).isTrue();
    }

    @Test
    void s3BucketCname() {
        assertTruePositive("old-bucket.s3.amazonaws.com", "AWS S3", "NoSuchBucket");
    }

    @Test
    void s3WebsiteCnameWithRegionVariant() {
        assertTruePositive("assets.s3-website-us-east-1.amazonaws.com", "AWS S3", "NoSuchBucket");
    }

    @Test
    void githubPagesCname() {
        assertTruePositive("myorg.github.io", "GitHub Pages", "There isn't a GitHub Pages site here");
    }

    @Test
    void herokuCname() {
        assertTruePositive("myapp.herokuapp.com", "Heroku", "No such app");
    }

    @Test
    void azureWebAppCname() {
        assertTruePositive("myapp.azurewebsites.net", "Azure Web App", "404 Web Site not found");
    }

    @Test
    void zendeskCname() {
        assertTruePositive("myorg.zendesk.com", "Zendesk", "Help Center Closed");
    }

    @Test
    void shopifyCname() {
        assertTruePositive("myshop.myshopify.com", "Shopify", "Sorry, this shop is currently unavailable");
    }

    @Test
    void fastlyCname() {
        assertTruePositive("assets.fastly.net", "Fastly", "Fastly error: unknown domain");
    }

    @Test
    void matchedProviderButBodyDoesNotContainFingerprint_mustNotFlag() {
        Optional<DanglingCnameDecisionLogic.TakeoverService> match =
                DanglingCnameDecisionLogic.matchProvider("myapp.herokuapp.com");
        assertThat(match).isPresent();
        assertThat(DanglingCnameDecisionLogic.isUnclaimed(match.get(), "<html>Welcome to My App</html>")).isFalse();
    }

    @Test
    void cnameMatchingNoKnownProvider_noCheckApplies() {
        assertThat(DanglingCnameDecisionLogic.matchProvider("db-primary.internal.example.com")).isEmpty();
    }

    @Test
    void nullOrBlankCname_noCheckApplies() {
        assertThat(DanglingCnameDecisionLogic.matchProvider(null)).isEmpty();
        assertThat(DanglingCnameDecisionLogic.matchProvider("")).isEmpty();
    }

    @Test
    void nullResponseBody_neverFlagged() {
        Optional<DanglingCnameDecisionLogic.TakeoverService> match =
                DanglingCnameDecisionLogic.matchProvider("bucket.s3.amazonaws.com");
        assertThat(match).isPresent();
        assertThat(DanglingCnameDecisionLogic.isUnclaimed(match.get(), null)).isFalse();
    }
}
