package org.freedonia.bloodhound.server.bootstrap;

import org.freedonia.bloodhound.server.orgs.Organization;
import org.freedonia.bloodhound.server.orgs.OrganizationRepository;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Creates the first organization + ADMIN user on a fresh database so there's
 * a way to log in at all. Idempotent: only acts when no users exist yet, so
 * it's safe to leave the BOOTSTRAP_* env vars set across restarts.
 */
@Component
public class BootstrapRunner implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(BootstrapRunner.class);

    private final UserRepository userRepository;
    private final OrganizationRepository organizationRepository;
    private final PasswordEncoder passwordEncoder;

    private final String orgName;
    private final String orgSlug;
    private final String adminEmail;
    private final String adminPassword;

    public BootstrapRunner(
            UserRepository userRepository,
            OrganizationRepository organizationRepository,
            PasswordEncoder passwordEncoder,
            @Value("${bloodhound.bootstrap.org-name:}") String orgName,
            @Value("${bloodhound.bootstrap.org-slug:}") String orgSlug,
            @Value("${bloodhound.bootstrap.admin-email:}") String adminEmail,
            @Value("${bloodhound.bootstrap.admin-password:}") String adminPassword) {
        this.userRepository = userRepository;
        this.organizationRepository = organizationRepository;
        this.passwordEncoder = passwordEncoder;
        this.orgName = orgName;
        this.orgSlug = orgSlug;
        this.adminEmail = adminEmail;
        this.adminPassword = adminPassword;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (userRepository.count() > 0) {
            log.info("bootstrap: users already exist, skipping admin bootstrap");
            return;
        }
        if (isBlank(orgName) || isBlank(orgSlug) || isBlank(adminEmail) || isBlank(adminPassword)) {
            log.warn(
                    "bootstrap: BOOTSTRAP_ORG_NAME/BOOTSTRAP_ORG_SLUG/BOOTSTRAP_ADMIN_EMAIL/"
                            + "BOOTSTRAP_ADMIN_PASSWORD are not fully set - no admin user created, nobody will be "
                            + "able to log in until this is configured and the app restarts");
            return;
        }

        Organization org =
                organizationRepository.findBySlug(orgSlug).orElseGet(() -> organizationRepository.insert(orgName, orgSlug));
        var admin =
                userRepository.insertLocalAdmin(org.id(), adminEmail, "Admin", passwordEncoder.encode(adminPassword));
        log.info("bootstrap: created organization '{}' and admin user '{}'", org.slug(), admin.email());
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
