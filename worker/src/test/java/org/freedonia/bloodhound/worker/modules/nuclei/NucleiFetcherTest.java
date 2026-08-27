package org.freedonia.bloodhound.worker.modules.nuclei;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.freedonia.bloodhound.common.scanmodule.ScanModuleException;
import org.junit.jupiter.api.Test;

class NucleiFetcherTest {

    private final NucleiFetcher fetcher = new NucleiFetcher();

    /**
     * A hostname starting with '-' would land right after "-target" in nuclei's argv, where its own CLI
     * flag parser sees it rather than a scan target. Rejected before the process is ever started - this
     * assertion would still pass even if nuclei weren't installed, since the check runs first.
     */
    @Test
    void hostnameStartingWithDash_rejectedBeforeInvokingNuclei() {
        assertThatThrownBy(() -> fetcher.scanJsonLines("-target-injection.example.com"))
                .isInstanceOf(ScanModuleException.class)
                .hasMessageContaining("refusing to pass a hostname starting with '-'");
    }

    @Test
    void bareDash_rejected() {
        assertThatThrownBy(() -> fetcher.scanJsonLines("-oX"))
                .isInstanceOf(ScanModuleException.class)
                .hasMessageContaining("refusing to pass a hostname starting with '-'");
    }
}
