package org.freedonia.bloodhound.server.auth;

import java.util.List;
import org.freedonia.bloodhound.server.orgs.User;
import org.freedonia.bloodhound.server.orgs.UserRepository;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        List<User> matches = userRepository.findLocalActiveByEmail(email);
        if (matches.isEmpty()) {
            throw new UsernameNotFoundException("no active local user with that email");
        }
        if (matches.size() > 1) {
            throw new AuthenticationServiceException(
                    "email is ambiguous across organizations - org-scoped login is not yet implemented");
        }
        return new AuthenticatedUserPrincipal(matches.get(0));
    }
}
