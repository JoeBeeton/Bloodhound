package org.freedonia.bloodhound.server.orgs;

import jakarta.validation.Valid;
import org.freedonia.bloodhound.server.auth.JwtPrincipal;
import org.freedonia.bloodhound.server.orgs.dto.ChangePasswordRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Self-service actions for the currently-authenticated user - closes the loop
 * for an admin-created user (or the bootstrap admin, stuck with whatever
 * .env placeholder was configured) to actually rotate off a temporary or
 * placeholder password. Only ever acts on the caller's own account.
 */
@RestController
@RequestMapping("/api/v1/users/me")
public class UserSelfController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserSelfController(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PatchMapping("/password")
    public ResponseEntity<Void> changePassword(
            @Valid @RequestBody ChangePasswordRequest request, @AuthenticationPrincipal JwtPrincipal principal) {
        User user = userRepository.findById(principal.userId()).orElseThrow();
        if (!"LOCAL".equals(user.identitySource()) || user.passwordHash() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "this account doesn't use a local password");
        }
        if (!passwordEncoder.matches(request.currentPassword(), user.passwordHash())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "current password is incorrect");
        }
        userRepository.updatePasswordHash(user.id(), passwordEncoder.encode(request.newPassword()));
        return ResponseEntity.noContent().build();
    }
}
