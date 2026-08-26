package org.freedonia.bloodhound.worker.modules.breach;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.freedonia.bloodhound.common.scanmodule.ScanContext;
import org.freedonia.bloodhound.worker.modules.breach.BreachCorrelationSource.BreachRecord;
import org.junit.jupiter.api.Test;

class BreachCorrelationModuleTest {

    private final BreachCorrelationSource source = mock(BreachCorrelationSource.class);
    private final ScanContext context = new ScanContext(UUID.randomUUID(), "example.com", List.of(), Map.of());

    @Test
    void noApiKeyConfigured_disabledAndSourceNeverCalled() throws Exception {
        BreachCorrelationModule module = new BreachCorrelationModule(source, "");

        var result = module.execute(context);

        assertThat(result.findings()).isEmpty();
        assertThat(result.rawMetadata()).containsEntry("enabled", false);
        verify(source, never()).lookup(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void blankApiKeyTreatedSameAsUnset() throws Exception {
        BreachCorrelationModule module = new BreachCorrelationModule(source, "   ");

        var result = module.execute(context);

        assertThat(result.rawMetadata()).containsEntry("enabled", false);
        verify(source, never()).lookup(org.mockito.ArgumentMatchers.any());
    }

    @Test
    void apiKeyConfigured_looksUpAndMapsFindings() throws Exception {
        BreachCorrelationModule module = new BreachCorrelationModule(source, "real-key");
        when(source.lookup("example.com"))
                .thenReturn(List.of(new BreachRecord("ExampleCorp2019", "A breach", Instant.parse("2019-01-01T00:00:00Z"))));

        var result = module.execute(context);

        assertThat(result.findings()).hasSize(1);
        assertThat(result.findings().get(0).ruleId()).isEqualTo("BREACH_EMAIL_DOMAIN_IN_KNOWN_BREACH");
        assertThat(result.findings().get(0).affectedAsset()).isEqualTo("example.com");
        assertThat(result.rawMetadata()).containsEntry("enabled", true).containsEntry("recordCount", 1);
    }

    @Test
    void apiKeyConfiguredButNoBreachesFound_emptyFindings() throws Exception {
        BreachCorrelationModule module = new BreachCorrelationModule(source, "real-key");
        when(source.lookup("example.com")).thenReturn(List.of());

        var result = module.execute(context);

        assertThat(result.findings()).isEmpty();
        assertThat(result.rawMetadata()).containsEntry("enabled", true).containsEntry("recordCount", 0);
    }
}
