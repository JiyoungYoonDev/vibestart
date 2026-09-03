package com.auth.auth_service.config;

import com.auth.auth_service.common.GlobalExceptionHandler;
import com.auth.auth_service.health.HealthController;
import com.auth.auth_service.security.AuthEntryPoint;
import com.auth.auth_service.security.CustomUserDetailsService;
import com.auth.auth_service.security.JwtService;
import com.auth.auth_service.security.TokenBlacklistService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for CorsConfig.
 *
 * Strategy:
 *  1. @WebMvcTest slice — exercises CORS behaviour through the full MVC pipeline
 *     via MockMvc. CorsConfig and GlobalExceptionHandler are imported explicitly
 *     because @WebMvcTest does not pick them up from package scanning.
 *  2. Pure unit test — instantiates CorsConfig via reflection (to set @Value
 *     fields) and asserts the bean factory method returns a non-null configurer.
 *
 * Property values are supplied via @TestPropertySource so no application.yml
 * from the main source set leaks into these tests.
 */
@WebMvcTest(HealthController.class)
@Import({CorsConfig.class, GlobalExceptionHandler.class, AuthEntryPoint.class})
@TestPropertySource(properties = {
        "spring.cors.allowed-origins=http://localhost:3000,http://allowed.example.com",
        "spring.cors.allowed-methods=GET,POST,PUT,DELETE,OPTIONS",
        "spring.cors.allowed-headers=Content-Type,Authorization,X-Requested-With"
})
class CorsConfigTest {

    private static final String ALLOWED_ORIGIN_1  = "http://localhost:3000";
    private static final String ALLOWED_ORIGIN_2  = "http://allowed.example.com";
    private static final String DISALLOWED_ORIGIN = "http://evil.com";
    private static final String HEALTH_PATH       = "/api/v1/health";
    private static final String NON_API_PATH      = "/non-api-path";

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    // =========================================================================
    // Preflight (OPTIONS) — allowed origins
    // =========================================================================

    @Test
    void preflight_fromAllowedOrigin_returnsOkStatus() throws Exception {
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", ALLOWED_ORIGIN_1)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(status().isOk());
    }

    @Test
    void preflight_fromAllowedOrigin_returnsAllowOriginHeader() throws Exception {
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", ALLOWED_ORIGIN_1)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN_1));
    }

    @Test
    void preflight_fromAllowedOrigin_allowCredentialsIsTrue() throws Exception {
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", ALLOWED_ORIGIN_1)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
    }

    @Test
    void preflight_fromAllowedOrigin_returnsAllowMethodsHeader() throws Exception {
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", ALLOWED_ORIGIN_1)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().exists("Access-Control-Allow-Methods"));
    }

    @Test
    void preflight_fromAllowedOrigin_returnsAllowHeadersHeader() throws Exception {
        // Access-Control-Allow-Headers is only echoed by Spring when the browser
        // sends Access-Control-Request-Headers in the preflight request.
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", ALLOWED_ORIGIN_1)
                        .header("Access-Control-Request-Method", "GET")
                        .header("Access-Control-Request-Headers", "Content-Type"))
                .andExpect(header().exists("Access-Control-Allow-Headers"));
    }

    @Test
    void preflight_fromSecondAllowedOrigin_returnsAllowOriginHeader() throws Exception {
        // Verifies that the second value in the comma-separated allowed-origins
        // property is also accepted by the CORS configuration.
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", ALLOWED_ORIGIN_2)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN_2));
    }

    // =========================================================================
    // Preflight (OPTIONS) — disallowed origin
    // =========================================================================

    @Test
    void preflight_fromDisallowedOrigin_doesNotReturnAllowOriginHeader() throws Exception {
        // Spring's CORS processing omits the Allow-Origin header entirely when
        // the origin is not in the allowed list, rather than returning a 4xx.
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", DISALLOWED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    @Test
    void preflight_fromDisallowedOrigin_doesNotAllowCredentials() throws Exception {
        mockMvc.perform(options(HEALTH_PATH)
                        .header("Origin", DISALLOWED_ORIGIN)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Credentials"));
    }

    // =========================================================================
    // Simple GET requests — CORS response headers on actual requests
    // =========================================================================

    @Test
    void get_fromAllowedOrigin_returnsAllowOriginHeader() throws Exception {
        mockMvc.perform(get(HEALTH_PATH)
                        .header("Origin", ALLOWED_ORIGIN_1))
                .andExpect(header().string("Access-Control-Allow-Origin", ALLOWED_ORIGIN_1));
    }

    @Test
    void get_fromDisallowedOrigin_doesNotReturnAllowOriginHeader() throws Exception {
        mockMvc.perform(get(HEALTH_PATH)
                        .header("Origin", DISALLOWED_ORIGIN))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    // =========================================================================
    // Path-mapping — CORS only applies to /api/**
    // =========================================================================

    @Test
    void preflight_toNonApiPath_doesNotReturnCorsHeaders() throws Exception {
        // The CorsConfig maps only "/api/**". A preflight to any other path
        // should not receive CORS response headers.
        mockMvc.perform(options(NON_API_PATH)
                        .header("Origin", ALLOWED_ORIGIN_1)
                        .header("Access-Control-Request-Method", "GET"))
                .andExpect(header().doesNotExist("Access-Control-Allow-Origin"));
    }

    // =========================================================================
    // Pure unit test — no Spring context
    // =========================================================================

    @Test
    void corsConfigurer_returnsNonNullBean() throws Exception {
        // Arrange — create a CorsConfig instance and inject @Value fields via
        // reflection because there is no Spring context to do it automatically.
        CorsConfig config = new CorsConfig();

        Field originsField = CorsConfig.class.getDeclaredField("allowedOrigins");
        originsField.setAccessible(true);
        originsField.set(config, "http://localhost:3000");

        Field methodsField = CorsConfig.class.getDeclaredField("allowedMethods");
        methodsField.setAccessible(true);
        methodsField.set(config, "GET, POST");

        Field headersField = CorsConfig.class.getDeclaredField("allowedHeaders");
        headersField.setAccessible(true);
        headersField.set(config, "Content-Type, Authorization");

        // Act
        WebMvcConfigurer configurer = config.corsConfigurer();

        // Assert
        assertThat(configurer).isNotNull();
    }
}
