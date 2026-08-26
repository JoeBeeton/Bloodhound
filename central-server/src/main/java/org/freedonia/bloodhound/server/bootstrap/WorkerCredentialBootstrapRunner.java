package org.freedonia.bloodhound.server.bootstrap;

import java.util.Set;
import org.freedonia.bloodhound.server.auth.WorkerCredentialRepository;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

/**
 * Seeds a worker_credentials row from WORKER_API_KEY on first boot, so
 * workers built with that same env var can authenticate to /api/v1/jobs/**.
 * Idempotent: only inserts if no credential with this key's hash exists yet,
 * so it's safe to leave WORKER_API_KEY set across restarts.
 */
@Component
public class WorkerCredentialBootstrapRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(WorkerCredentialBootstrapRunner.class);

    private final WorkerCredentialRepository workerCredentialRepository;
    private final String apiKey;

    public WorkerCredentialBootstrapRunner(
            WorkerCredentialRepository workerCredentialRepository,
            @Value("${bloodhound.worker.api-key:}") String apiKey) {
        this.workerCredentialRepository = workerCredentialRepository;
        this.apiKey = apiKey;
    }

    // Every placeholder value .env.example has ever shipped for this key -
    // see JwtService's identical check for why this is a startup WARNING,
    // not a hard fail, and why old values are kept rather than replaced.
    private static final Set<String> KNOWN_PLACEHOLDER_KEYS =
            Set.of("change-me-dev-only-not-a-real-secret", "<generate-with-openssl-rand-base64-32>");

    @Override
    public void run(ApplicationArguments args) {
        if (apiKey == null || apiKey.isBlank()) {
            log.warn("bootstrap: WORKER_API_KEY is not set - no worker credential seeded, workers cannot authenticate");
            return;
        }
        if (KNOWN_PLACEHOLDER_KEYS.contains(apiKey)) {
            log.warn(
                    "SECURITY: WORKER_API_KEY is still the example placeholder from .env.example. Anyone who has "
                            + "seen that file can authenticate as a worker and claim/report scan jobs. Rotate it to "
                            + "a real random secret before this is exposed beyond a trusted local machine.");
        }
        String hash = HashUtil.sha256Hex(apiKey);
        if (workerCredentialRepository.existsByKeyHash(hash)) {
            log.info("bootstrap: worker credential already seeded, skipping");
            return;
        }
        workerCredentialRepository.insert("bootstrap", hash);
        log.info("bootstrap: seeded worker credential from WORKER_API_KEY");
    }
}
