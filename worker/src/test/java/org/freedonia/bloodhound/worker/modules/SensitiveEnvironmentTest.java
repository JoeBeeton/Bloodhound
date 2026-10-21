package org.freedonia.bloodhound.worker.modules;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SensitiveEnvironmentTest {

    @Test
    void removesAllKnownCredentialVariables() {
        Map<String, String> env = new HashMap<>();
        env.put("WORKER_API_KEY", "secret1");
        env.put("ZAP_API_KEY", "secret2");
        env.put("SCREENSHOTTER_API_KEY", "secret3");
        env.put("HIBP_API_KEY", "secret4");
        env.put("PATH", "/usr/bin");

        SensitiveEnvironment.scrub(env);

        assertThat(env).containsOnlyKeys("PATH");
    }

    @Test
    void toleratesAMapMissingSomeOfTheVariables() {
        Map<String, String> env = new HashMap<>();
        env.put("PATH", "/usr/bin");
        env.put("HOME", "/home/worker");

        SensitiveEnvironment.scrub(env);

        assertThat(env).containsOnlyKeys("PATH", "HOME");
    }
}
