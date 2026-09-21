package org.freedonia.bloodhound.server.eol;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class EolVersionMatcherTest {

    private static EolRelease release(String cycle) {
        return new EolRelease(cycle, false, null, true, cycle + ".0");
    }

    @Test
    void versionMatchesTheCycleWhoseSegmentsItStartsWith() {
        List<EolRelease> releases = List.of(release("1.24"), release("1.25"));
        Optional<EolRelease> match = EolVersionMatcher.match("1.24.3", releases);
        assertThat(match).isPresent();
        assertThat(match.get().releaseCycle()).isEqualTo("1.24");
    }

    @Test
    void versionDoesNotMatchARawStringPrefixThatIsntASegmentPrefix() {
        // "1.2" is a raw string prefix of "1.24.3" but NOT a segment-wise prefix
        // (segment 2 is "2" vs "24") - must not match.
        List<EolRelease> releases = List.of(release("1.2"));
        assertThat(EolVersionMatcher.match("1.24.3", releases)).isEmpty();
    }

    @Test
    void mostSpecificCycleWinsWhenMultipleSegmentsMatch() {
        List<EolRelease> releases = List.of(release("1"), release("1.24"));
        Optional<EolRelease> match = EolVersionMatcher.match("1.24.3", releases);
        assertThat(match).isPresent();
        assertThat(match.get().releaseCycle()).isEqualTo("1.24");
    }

    @Test
    void versionNewerThanAnyKnownCycle_noMatch() {
        List<EolRelease> releases = List.of(release("1.24"), release("1.25"));
        assertThat(EolVersionMatcher.match("2.0.0", releases)).isEmpty();
    }

    @Test
    void singleSegmentCycleName_matchesByFirstSegment() {
        List<EolRelease> releases = List.of(release("8"));
        Optional<EolRelease> match = EolVersionMatcher.match("8.2.1", releases);
        assertThat(match).isPresent();
        assertThat(match.get().releaseCycle()).isEqualTo("8");
    }

    @Test
    void exactVersionEqualToCycleName_matches() {
        List<EolRelease> releases = List.of(release("1.24"));
        assertThat(EolVersionMatcher.match("1.24", releases)).isPresent();
    }

    @Test
    void emptyReleaseList_noMatch() {
        assertThat(EolVersionMatcher.match("1.24.3", List.of())).isEmpty();
    }

    @Test
    void blankOrNullVersion_noMatch() {
        List<EolRelease> releases = List.of(release("1.24"));
        assertThat(EolVersionMatcher.match("", releases)).isEmpty();
        assertThat(EolVersionMatcher.match(null, releases)).isEmpty();
    }

    @Test
    void matchedReleaseCarriesItsOwnEolData() {
        EolRelease eolRelease = new EolRelease("1.29", true, LocalDate.parse("2026-05-13"), false, "1.29.8");
        Optional<EolRelease> match = EolVersionMatcher.match("1.29.5", List.of(eolRelease));
        assertThat(match).contains(eolRelease);
    }
}
