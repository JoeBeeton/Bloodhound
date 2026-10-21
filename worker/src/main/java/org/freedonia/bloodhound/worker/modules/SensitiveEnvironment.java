package org.freedonia.bloodhound.worker.modules;

import java.util.Map;
import java.util.Set;

/**
 * A security review found that every direct-subprocess scanner this worker invokes (katana,
 * nuclei) inherits the full process environment by default via {@code ProcessBuilder}, including
 * {@code WORKER_API_KEY}, {@code ZAP_API_KEY}, {@code SCREENSHOTTER_API_KEY}, and {@code
 * HIBP_API_KEY}. Those two tools are the ones that parse attacker-influenced content (katana
 * fetches and JS-parses pages/scripts a monitored or competitor site serves; nuclei runs a
 * 10,000+ template corpus, some of it code-execution-capable, against the target) - a bug in
 * either one that achieves code execution would be holding a control-plane credential, not just
 * crashing a scan. Neither tool needs any of these to do its job, so removing them from the
 * child's environment before start costs nothing legitimate.
 */
public final class SensitiveEnvironment {

    public static final Set<String> CREDENTIAL_VARS =
            Set.of("WORKER_API_KEY", "ZAP_API_KEY", "SCREENSHOTTER_API_KEY", "HIBP_API_KEY");

    private SensitiveEnvironment() {}

    /** Mutates {@code env} in place - call with {@code ProcessBuilder#environment()} before {@code start()}. */
    public static void scrub(Map<String, String> env) {
        CREDENTIAL_VARS.forEach(env::remove);
    }
}
