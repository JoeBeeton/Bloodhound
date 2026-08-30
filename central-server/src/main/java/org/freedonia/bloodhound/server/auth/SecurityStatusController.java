package org.freedonia.bloodhound.server.auth;

import org.freedonia.bloodhound.server.bootstrap.WorkerCredentialBootstrapRunner;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Surfaces deployment-wide security misconfigurations that previously only ever appeared as a
 * startup log line - a security review found an admin using the UI had no way to discover, say,
 * a still-placeholder JWT signing key short of reading server logs, even though anyone who has
 * ever seen this repository's .env.example can forge valid login tokens for any user until it's
 * rotated. ADMIN-only: this is an operational/security concern only an admin would act on, not
 * data any authenticated user needs.
 */
@RestController
@RequestMapping("/api/v1/admin/security-status")
@PreAuthorize("hasRole('ADMIN')")
public class SecurityStatusController {

    private final JwtService jwtService;
    private final WorkerCredentialBootstrapRunner workerCredentialBootstrapRunner;

    public SecurityStatusController(
            JwtService jwtService, WorkerCredentialBootstrapRunner workerCredentialBootstrapRunner) {
        this.jwtService = jwtService;
        this.workerCredentialBootstrapRunner = workerCredentialBootstrapRunner;
    }

    public record SecurityStatus(boolean jwtSigningKeyIsPlaceholder, boolean workerApiKeyIsPlaceholder) {}

    @GetMapping
    public SecurityStatus get() {
        return new SecurityStatus(
                jwtService.isSigningKeyPlaceholder(), workerCredentialBootstrapRunner.isApiKeyPlaceholder());
    }
}
