package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Covers the process-lifecycle/watchdog half of the fix (see the class's own javadoc) with a real
 * subprocess, not a mock - a genuine {@code sh} process that trickles output forever without ever
 * exiting is the exact shape a hung/misbehaving CLI tool would produce, and the case the pre-fix
 * code would have blocked on forever reading stdout before its own hard-timeout check ever ran.
 * No real subfinder/naabu binary needed to exercise this - it's pure process-lifecycle plumbing,
 * identical regardless of which command is actually run.
 */
class ExternalCliSubdomainSourceTest {

    private static final class HangingSource extends ExternalCliSubdomainSource {
        @Override
        protected List<String> command(String rootDomain) {
            return List.of("sh", "-c", "while true; do printf x; sleep 2; done");
        }

        @Override
        protected List<String> parseOutput(String stdout, String rootDomain) {
            return List.of(stdout); // not the point of this test - just needs to not throw
        }

        @Override
        public String sourceName() {
            return "HANGING_TEST_SOURCE";
        }
    }

    @Test
    void hangingProcess_isForceKilledWithinTheHardTimeout_ratherThanHangingForever() {
        long start = System.currentTimeMillis();

        List<String> result = new HangingSource().discover("example.com");

        long elapsedMs = System.currentTimeMillis() - start;
        // The timeout path returns List.of() (this source found nothing), not the trickled
        // output - matches the class's own "a failing source shouldn't fail the whole scan"
        // philosophy.
        assertThat(result).isEmpty();
        // Comfortably above the class's own 75s HARD_TIMEOUT_SECONDS for scheduling/CI jitter,
        // nowhere near "hangs forever" - before the fix, this test would never have completed.
        assertThat(elapsedMs).isLessThan(90_000);
    }
}
