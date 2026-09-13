package org.freedonia.bloodhound.worker.modules.nuclei;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
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

    /**
     * The fatal line nuclei actually printed for two weeks while every scan reported 0 findings - it is
     * always the last thing on stderr, so a bounded tail must keep it even after arbitrary earlier noise.
     */
    @Test
    void stderrTail_keepsTheFinalFatalLineAfterMoreOutputThanItsCapacity() throws Exception {
        String noise = "[WRN] some template warning\n".repeat(500); // ~14KB, well past the 4KB tail
        String fatal = "[FTL] Could not run nuclei: no templates provided for scan";
        NucleiFetcher.StderrTail tail = new NucleiFetcher.StderrTail();
        tail.drain(new ByteArrayInputStream((noise + fatal + "\n").getBytes(StandardCharsets.UTF_8)));
        assertThat(tail.text()).endsWith(fatal);
        assertThat(tail.text().length()).isLessThanOrEqualTo(4096);
    }

    @Test
    void stderrTail_shortOutputIsReturnedVerbatim() throws Exception {
        NucleiFetcher.StderrTail tail = new NucleiFetcher.StderrTail();
        tail.drain(new ByteArrayInputStream("[FTL] boom\n".getBytes(StandardCharsets.UTF_8)));
        assertThat(tail.text()).isEqualTo("[FTL] boom");
    }

    @Test
    void stderrTail_emptyStderr_isEmptyString() throws Exception {
        NucleiFetcher.StderrTail tail = new NucleiFetcher.StderrTail();
        tail.drain(new ByteArrayInputStream(new byte[0]));
        assertThat(tail.text()).isEmpty();
    }
}
