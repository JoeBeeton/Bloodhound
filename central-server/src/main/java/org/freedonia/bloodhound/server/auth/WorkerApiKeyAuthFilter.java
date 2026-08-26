package org.freedonia.bloodhound.server.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.freedonia.bloodhound.server.security.HashUtil;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Validates the X-Worker-Api-Key header and, if valid, authenticates the
 * request as ROLE_WORKER with the credential's label as principal - a
 * distinct principal type from JwtPrincipal, so worker keys can never satisfy
 * a user route (SecurityConfig requires hasAnyRole(ADMIN,ANALYST,VIEWER)
 * there) and user JWTs can never satisfy /api/v1/jobs/** (hasRole(WORKER)).
 * Constructed directly by SecurityConfig (not a @Component), same reasoning
 * as JwtAuthenticationFilter: avoids Spring Boot double-registering it as a
 * generic servlet filter outside the security chain.
 */
public class WorkerApiKeyAuthFilter extends OncePerRequestFilter {

    private static final String HEADER = "X-Worker-Api-Key";

    private final WorkerCredentialRepository workerCredentialRepository;

    public WorkerApiKeyAuthFilter(WorkerCredentialRepository workerCredentialRepository) {
        this.workerCredentialRepository = workerCredentialRepository;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String apiKey = request.getHeader(HEADER);
        if (apiKey != null && !apiKey.isBlank()) {
            workerCredentialRepository.findActiveByKeyHash(HashUtil.sha256Hex(apiKey)).ifPresent(credential -> {
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_WORKER"));
                var authentication = new UsernamePasswordAuthenticationToken(credential.label(), null, authorities);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            });
        }
        filterChain.doFilter(request, response);
    }
}
