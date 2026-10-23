package org.freedonia.bloodhound.server.target;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class HostnamePatternTest {

    @Test
    void matchesOrdinaryHostnames() {
        assertThat(HostnamePattern.PATTERN.matcher("example.com").matches()).isTrue();
        assertThat(HostnamePattern.PATTERN.matcher("sub.example.com").matches()).isTrue();
        assertThat(HostnamePattern.PATTERN.matcher("a-b.example.co.uk").matches()).isTrue();
    }

    @Test
    void rejectsAFragmentSmuggledHostname() {
        // The exact shape a security review found slipping past SubdomainController#add's old
        // suffix-only check: java.net.URI parses this string's host as just "central-server",
        // dropping everything from "#" on as a fragment.
        assertThat(HostnamePattern.PATTERN.matcher("central-server#.example.com").matches()).isFalse();
    }

    @Test
    void rejectsEmptyAndBareLabels() {
        assertThat(HostnamePattern.PATTERN.matcher("").matches()).isFalse();
        assertThat(HostnamePattern.PATTERN.matcher("example").matches()).isFalse();
        assertThat(HostnamePattern.PATTERN.matcher(".example.com").matches()).isFalse();
        assertThat(HostnamePattern.PATTERN.matcher("example..com").matches()).isFalse();
    }

    @Test
    void rejectsOtherSchemeAndPathCharacters() {
        assertThat(HostnamePattern.PATTERN.matcher("https://example.com").matches()).isFalse();
        assertThat(HostnamePattern.PATTERN.matcher("example.com/path").matches()).isFalse();
        assertThat(HostnamePattern.PATTERN.matcher("example.com:8080").matches()).isFalse();
    }
}
