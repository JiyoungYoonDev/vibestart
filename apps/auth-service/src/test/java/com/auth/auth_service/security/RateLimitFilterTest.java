package com.auth.auth_service.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

// OncePerRequestFilter tracks an "already filtered" attribute on the
// HttpServletRequest instance itself, so each simulated call here uses a
// *fresh* MockHttpServletRequest — reusing one instance across calls (as
// if it were the same in-flight request forwarding to itself) would
// silently skip doFilterInternal on every call after the first.
class RateLimitFilterTest {
    private final RateLimitFilter filter = new RateLimitFilter();

    private static MockHttpServletRequest request(String method, String path, String remoteAddr) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setRemoteAddr(remoteAddr);
        return request;
    }

    @Test
    void unmatchedPath_isNeverThrottled() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        for (int i = 0; i < 100; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request("GET", "/api/v1/auth/me", "203.0.113.1"), response, chain);
            assertThat(response.getStatus()).isEqualTo(200);
        }
    }

    @Test
    void login_allowsUpToCapacityThenReturns429() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        String ip = "203.0.113.5";

        for (int i = 0; i < 10; i++) {
            MockHttpServletResponse response = new MockHttpServletResponse();
            filter.doFilter(request("POST", "/api/v1/auth/login", ip), response, chain);
            assertThat(response.getStatus()).isEqualTo(200);
        }
        verify(chain, times(10)).doFilter(any(), any());

        MockHttpServletResponse blocked = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/api/v1/auth/login", ip), blocked, chain);

        assertThat(blocked.getStatus()).isEqualTo(429);
        assertThat(blocked.getHeader("Retry-After")).isNotNull();
        assertThat(blocked.getContentAsString()).contains("Too many requests");
        verify(chain, times(10)).doFilter(any(), any());
    }

    @Test
    void loginAndSignup_haveIndependentBudgetsForTheSameIp() throws Exception {
        FilterChain chain = mock(FilterChain.class);
        String ip = "203.0.113.7";

        for (int i = 0; i < 10; i++) {
            filter.doFilter(request("POST", "/api/v1/auth/login", ip), new MockHttpServletResponse(), chain);
        }
        MockHttpServletResponse loginBlocked = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/api/v1/auth/login", ip), loginBlocked, chain);
        assertThat(loginBlocked.getStatus()).isEqualTo(429);

        // Signup is a separate rule (5/hour) — exhausting login's budget
        // must not bleed into it.
        MockHttpServletResponse signupAllowed = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/api/v1/auth/signup", ip), signupAllowed, chain);
        assertThat(signupAllowed.getStatus()).isEqualTo(200);
    }

    @Test
    void differentIps_getIndependentBudgets() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        for (int i = 0; i < 10; i++) {
            filter.doFilter(request("POST", "/api/v1/auth/login", "203.0.113.10"), new MockHttpServletResponse(), chain);
        }
        MockHttpServletResponse aBlocked = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/api/v1/auth/login", "203.0.113.10"), aBlocked, chain);
        assertThat(aBlocked.getStatus()).isEqualTo(429);

        MockHttpServletResponse bAllowed = new MockHttpServletResponse();
        filter.doFilter(request("POST", "/api/v1/auth/login", "203.0.113.20"), bAllowed, chain);
        assertThat(bAllowed.getStatus()).isEqualTo(200);
    }

    @Test
    void trustsLastHopOfForwardedForHeader_notTheClientSuppliedFirstHop() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        for (int i = 0; i < 10; i++) {
            MockHttpServletRequest req = request("POST", "/api/v1/auth/login", "10.0.0.1");
            req.addHeader("X-Forwarded-For", "9.9.9.9, 203.0.113.99");
            filter.doFilter(req, new MockHttpServletResponse(), chain);
        }
        MockHttpServletRequest exhausted = request("POST", "/api/v1/auth/login", "10.0.0.1");
        exhausted.addHeader("X-Forwarded-For", "9.9.9.9, 203.0.113.99");
        MockHttpServletResponse blocked = new MockHttpServletResponse();
        filter.doFilter(exhausted, blocked, chain);
        assertThat(blocked.getStatus()).isEqualTo(429);

        MockHttpServletRequest sameRealIp = request("POST", "/api/v1/auth/login", "10.0.0.1");
        sameRealIp.addHeader("X-Forwarded-For", "1.1.1.1, 203.0.113.99");
        MockHttpServletResponse alsoBlocked = new MockHttpServletResponse();
        filter.doFilter(sameRealIp, alsoBlocked, chain);
        assertThat(alsoBlocked.getStatus()).isEqualTo(429);
    }
}
