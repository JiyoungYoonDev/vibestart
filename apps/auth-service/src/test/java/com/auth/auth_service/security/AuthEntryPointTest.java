package com.auth.auth_service.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for AuthEntryPoint.
 * No Spring context — MockHttpServletRequest/Response stand in for the
 * servlet API, and a real ObjectMapper is used to exercise the actual
 * serialization AuthEntryPoint performs.
 */
class AuthEntryPointTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AuthEntryPoint authEntryPoint = new AuthEntryPoint(objectMapper);

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AuthenticationException authException;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        request.setRequestURI("/api/v1/auth/me");
        response = new MockHttpServletResponse();
        authException = new InsufficientAuthenticationException("Full authentication is required");
    }

    // ── HTTP status ────────────────────────────────────────────────────────────

    @Test
    void commence_returns401Status() throws Exception {
        authEntryPoint.commence(request, response, authException);

        assertThat(response.getStatus()).isEqualTo(401);
    }

    // ── Content type ───────────────────────────────────────────────────────────

    @Test
    void commence_returnsJsonContentType() throws Exception {
        authEntryPoint.commence(request, response, authException);

        assertThat(response.getContentType()).isEqualTo("application/json");
    }

    // ── Response body shape ────────────────────────────────────────────────────

    @Test
    void commence_returnsErrorResponseBody() throws Exception {
        authEntryPoint.commence(request, response, authException);

        JsonNode body = objectMapper.readTree(response.getContentAsString());

        assertThat(body.get("success").asBoolean()).isFalse();
        assertThat(body.get("code").asString()).isEqualTo("UNAUTHORIZED");
        assertThat(body.get("message").asString()).isEqualTo("Authentication required");
    }

    @Test
    void commence_bodyPathMatchesRequestUri() throws Exception {
        authEntryPoint.commence(request, response, authException);

        JsonNode body = objectMapper.readTree(response.getContentAsString());

        assertThat(body.get("path").asString()).isEqualTo("/api/v1/auth/me");
    }

    @Test
    void commence_bodyTimestampIsPresent() throws Exception {
        authEntryPoint.commence(request, response, authException);

        JsonNode body = objectMapper.readTree(response.getContentAsString());

        assertThat(body.get("timestamp").asString()).isNotBlank();
    }

    @Test
    void commence_bodyDetailsIsNull() throws Exception {
        authEntryPoint.commence(request, response, authException);

        JsonNode body = objectMapper.readTree(response.getContentAsString());

        assertThat(body.get("details").isNull()).isTrue();
    }

    @Test
    void commence_differentRequestUri_isReflectedInPath() throws Exception {
        request.setRequestURI("/api/v1/some-other-endpoint");

        authEntryPoint.commence(request, response, authException);

        JsonNode body = objectMapper.readTree(response.getContentAsString());
        assertThat(body.get("path").asString()).isEqualTo("/api/v1/some-other-endpoint");
    }
}
