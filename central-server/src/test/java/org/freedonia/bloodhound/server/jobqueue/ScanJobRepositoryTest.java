package org.freedonia.bloodhound.server.jobqueue;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/**
 * Covers the pure retry-backoff schedule only - the claim/heartbeat/fail SQL
 * itself is exercised for real against the live stack as part of manual
 * verification (Testcontainers-backed integration coverage of the queue
 * mechanics is a reasonable future addition, not added here).
 */
class ScanJobRepositoryTest {

    @Test
    void backoffGrowsWithAttemptNumber_cappedAtFiveMinutes() {
        assertThat(ScanJobRepository.backoffSeconds(1)).isEqualTo(30);
        assertThat(ScanJobRepository.backoffSeconds(2)).isEqualTo(120);
        assertThat(ScanJobRepository.backoffSeconds(3)).isEqualTo(300);
        assertThat(ScanJobRepository.backoffSeconds(10)).isEqualTo(300);
    }
}
