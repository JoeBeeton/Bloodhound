package org.freedonia.bloodhound.worker.modules;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class EvidenceRedactionTest {

    @Test
    void redact_neverContainsTheRawValue() {
        String redacted = EvidenceRedaction.redact("super-secret-token-value");
        assertThat(redacted).doesNotContain("super-secret-token-value");
    }

    @Test
    void redact_carriesLengthAndAHash() {
        String raw = "abc123";
        String redacted = EvidenceRedaction.redact(raw);
        assertThat(redacted).contains("6 chars").contains("sha256:");
    }

    @Test
    void redact_isDeterministic_sameInputSameHash() {
        assertThat(EvidenceRedaction.redact("same value")).isEqualTo(EvidenceRedaction.redact("same value"));
    }

    @Test
    void redact_differentInputsProduceDifferentHashes() {
        assertThat(EvidenceRedaction.redact("value one")).isNotEqualTo(EvidenceRedaction.redact("value two"));
    }

    @Test
    void redact_nullAndBlankPassThroughUnchanged() {
        assertThat(EvidenceRedaction.redact(null)).isNull();
        assertThat(EvidenceRedaction.redact("")).isEmpty();
        assertThat(EvidenceRedaction.redact("   ")).isEqualTo("   ");
    }

    @Test
    void redactAll_appliesToEveryElement() {
        List<String> redacted = EvidenceRedaction.redactAll(List.of("one", "two"));
        assertThat(redacted).hasSize(2);
        assertThat(redacted.get(0)).doesNotContain("one").contains("[redacted,");
        assertThat(redacted.get(1)).doesNotContain("two").contains("[redacted,");
    }
}
