package org.freedonia.bloodhound.worker.modules.exposure;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class SecretPatternScannerTest {

    @Test
    void nullOrBlankBody_noMatches() {
        assertThat(SecretPatternScanner.scan(null)).isEmpty();
        assertThat(SecretPatternScanner.scan("")).isEmpty();
        assertThat(SecretPatternScanner.scan("   ")).isEmpty();
    }

    @Test
    void plainConfig_noSecretShapedValues_noMatches() {
        String body = "APP_NAME=widgets\nAPP_ENV=production\nDEBUG=false\n";
        assertThat(SecretPatternScanner.scan(body)).isEmpty();
    }

    @Test
    void awsAccessKeyId_matched() {
        String body = "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\naws_region = us-east-1\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName).contains("AWS Access Key ID");
    }

    @Test
    void awsSecretAccessKey_matched() {
        String body = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName).contains("AWS Secret Access Key");
    }

    @Test
    void privateKeyBlockHeader_matched() {
        String body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName).contains("Private Key Block");
    }

    @Test
    void slackWebhookUrl_matched() {
        // Deliberately NOT shaped like a real Slack webhook's three slash-separated
        // T.../B.../token segments (a prior fixture using that exact shape tripped
        // GitHub's push-protection secret scanner despite being fake) - a single long
        // alphanumeric run after /services/ is enough to exercise this scanner's own
        // (much looser) pattern without looking like a real credential to anyone else's.
        String body = "SLACK_WEBHOOK=https://hooks.slack.com/services/notarealwebhooksecretplaceholder\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName).contains("Slack Webhook URL");
    }

    @Test
    void githubToken_matched() {
        String body = "GH_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789AB\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName).contains("GitHub Token");
    }

    @Test
    void credentialEmbeddedUrl_matched() {
        String body = "DATABASE_URL=postgres://appuser:hunter2verylongpassword@db.internal.example.com:5432/app\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName).contains("Credential-Embedded URL");
    }

    @Test
    void genericSecretAssignment_matched() {
        String body = "STRIPE_WEBHOOK_SECRET=\"whsec_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c\"\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName)
                .contains("Generic High-Entropy Secret Assignment");
    }

    @Test
    void redactedPreview_neverContainsFullMatchedValue() {
        String secret = "AKIAABCDEFGHIJKLMNOP";
        String body = "aws_access_key_id = " + secret + "\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).isNotEmpty();
        for (SecretPatternScanner.Match m : matches) {
            assertThat(m.redactedPreview()).doesNotContain(secret);
        }
    }

    @Test
    void duplicatePatternType_onlyReportedOnce() {
        String body = "AKIAABCDEFGHIJKLMNOP and also AKIAZZZZZZZZZZZZZZZZ appear twice\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        long awsKeyMatches =
                matches.stream().filter(m -> m.patternName().equals("AWS Access Key ID")).count();
        assertThat(awsKeyMatches).isEqualTo(1);
    }

    @Test
    void multiplePatternTypesInOneFile_allReported() {
        String body = "aws_access_key_id = AKIAABCDEFGHIJKLMNOP\n"
                + "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----\n";
        List<SecretPatternScanner.Match> matches = SecretPatternScanner.scan(body);
        assertThat(matches).extracting(SecretPatternScanner.Match::patternName)
                .contains("AWS Access Key ID", "Private Key Block");
    }
}
