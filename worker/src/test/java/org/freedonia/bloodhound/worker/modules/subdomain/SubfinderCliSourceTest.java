package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

/** Pure parser tests - zero process execution. */
class SubfinderCliSourceTest {

    @Test
    void parsesNewlineDelimitedOutput() {
        String stdout = "a.example.com\nb.example.com\nc.example.com\n";
        assertThat(SubfinderCliSource.parse(stdout))
                .containsExactly("a.example.com", "b.example.com", "c.example.com");
    }

    @Test
    void tolerantOfTrailingBlankLines() {
        String stdout = "a.example.com\nb.example.com\n\n\n";
        assertThat(SubfinderCliSource.parse(stdout)).containsExactly("a.example.com", "b.example.com");
    }

    @Test
    void lowercasesAndTrimsWhitespace() {
        String stdout = "  A.Example.com  \nB.EXAMPLE.COM\n";
        assertThat(SubfinderCliSource.parse(stdout)).containsExactly("a.example.com", "b.example.com");
    }

    @Test
    void emptyOrNullOutputYieldsEmptyList() {
        assertThat(SubfinderCliSource.parse("")).isEmpty();
        assertThat(SubfinderCliSource.parse("   \n  \n")).isEmpty();
        assertThat(SubfinderCliSource.parse(null)).isEmpty();
    }

    @Test
    void stderrOnlyFailureCaseYieldsEmptyList() {
        // Simulates what ExternalCliSubdomainSource passes to parseOutput when
        // the process produced nothing on stdout (its own failure handling
        // already logs/handles the process-level failure before this is ever
        // called with real stderr content).
        assertThat(SubfinderCliSource.parse("")).isEmpty();
    }

    @Test
    void sourceNameIsSubfinder() {
        assertThat(new SubfinderCliSource().sourceName()).isEqualTo("SUBFINDER");
    }
}
