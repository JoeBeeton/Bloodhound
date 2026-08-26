package org.freedonia.bloodhound.worker.modules.subdomain;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

class SubdomainMergeTest {

    @Test
    void hostnameFoundByOneSourceRecordsThatSource() {
        Map<String, TreeSet<String>> merged =
                SubdomainMerge.merge(Map.of("CRTSH", List.of("a.example.com")));
        assertThat(merged).containsOnlyKeys("a.example.com");
        assertThat(merged.get("a.example.com")).containsExactly("CRTSH");
    }

    @Test
    void hostnameFoundByBothSourcesAppearsOnceWithBothProvenance() {
        Map<String, TreeSet<String>> merged = SubdomainMerge.merge(Map.of(
                "CRTSH", List.of("shared.example.com"),
                "SUBFINDER", List.of("shared.example.com")));
        assertThat(merged).hasSize(1);
        assertThat(merged.get("shared.example.com")).containsExactly("CRTSH", "SUBFINDER");
    }

    @Test
    void oneSourceEmptyOtherSourceResultsStillUsed() {
        Map<String, TreeSet<String>> merged =
                SubdomainMerge.merge(Map.of("CRTSH", List.of(), "SUBFINDER", List.of("only-subfinder.example.com")));
        assertThat(merged).containsOnlyKeys("only-subfinder.example.com");
        assertThat(merged.get("only-subfinder.example.com")).containsExactly("SUBFINDER");
    }

    @Test
    void distinctHostnamesFromDifferentSourcesAllPreserved() {
        Map<String, TreeSet<String>> merged = SubdomainMerge.merge(Map.of(
                "CRTSH", List.of("a.example.com", "b.example.com"),
                "SUBFINDER", List.of("c.example.com")));
        assertThat(merged).containsOnlyKeys("a.example.com", "b.example.com", "c.example.com");
    }

    @Test
    void noSourcesYieldsEmptyMap() {
        assertThat(SubdomainMerge.merge(Map.of())).isEmpty();
    }
}
