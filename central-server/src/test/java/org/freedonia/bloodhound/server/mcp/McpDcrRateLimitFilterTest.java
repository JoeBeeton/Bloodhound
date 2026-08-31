package org.freedonia.bloodhound.server.mcp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Covers the pre-check half of the DCR rate-limit fix (see McpSecurityConfig /
 * DcrRateLimiter): an IP that has already registered MAX_REGISTRATIONS clients must be rejected
 * before Spring Authorization Server's own registration filter ever runs, not just have the
 * attempt recorded afterward.
 */
class McpDcrRateLimitFilterTest {

    private final DcrRateLimiter dcrRateLimiter = new DcrRateLimiter();
    private final McpDcrRateLimitFilter filter = new McpDcrRateLimitFilter(dcrRateLimiter);

    @Test
    void underTheLimit_passesThroughToTheRealRegistrationFilter() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/register");
        request.setRemoteAddr("10.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }

    @Test
    void ipOverTheLimit_blocksWith429AndRetryAfter_beforeTheRealFilterRuns() throws Exception {
        String ip = "10.0.0.2";
        for (int i = 0; i < 5; i++) {
            dcrRateLimiter.recordAttempt(ip);
        }
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth2/register");
        request.setRemoteAddr(ip);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain, never()).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isNotNull();
        assertThat(response.getContentAsString()).contains("request_denied");
    }

    @Test
    void nonRegistrationRequest_passesThroughRegardlessOfLimiterState() throws Exception {
        String ip = "10.0.0.3";
        for (int i = 0; i < 5; i++) {
            dcrRateLimiter.recordAttempt(ip);
        }
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/oauth2/register");
        request.setRemoteAddr(ip);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        filter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
