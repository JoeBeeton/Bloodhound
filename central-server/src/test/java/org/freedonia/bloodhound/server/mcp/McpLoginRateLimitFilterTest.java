package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import jakarta.servlet.FilterChain;
import org.freedonia.bloodhound.server.auth.LoginAttemptLimiter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Covers the pre-check half of the MCP consent-flow login fix (see McpSecurityConfig): a locked-
 * out email must be rejected before UsernamePasswordAuthenticationFilter ever runs a BCrypt
 * comparison, not just have the attempt recorded afterward.
 */
class McpLoginRateLimitFilterTest {

    private final LoginAttemptLimiter loginAttemptLimiter = new LoginAttemptLimiter();
    private final McpLoginRateLimitFilter filter = new McpLoginRateLimitFilter(loginAttemptLimiter);

    @Test
    void notYetLockedOut_passesThroughToTheRealAuthenticationFilter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setParameter("username", "user@example.com");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void lockedOutEmail_blocksBeforeAuthenticationRunsAtAll() throws Exception {
        String email = "victim@example.com";
        for (int i = 0; i < 10; i++) {
            loginAttemptLimiter.recordFailure(email);
        }
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/login");
        request.setParameter("username", email);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo("/login?error");
    }

    @Test
    void nonLoginSubmitRequest_passesThroughRegardlessOfLockoutState() throws Exception {
        // A locked-out email elsewhere in the app must not affect completely unrelated requests
        // through this chain (e.g. the initial GET /oauth2/authorize redirect, or GET /login
        // itself rendering the form) - the guard only ever applies to the actual POST /login
        // credential submission.
        String email = "victim@example.com";
        for (int i = 0; i < 10; i++) {
            loginAttemptLimiter.recordFailure(email);
        }
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/login");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
