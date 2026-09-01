package com.auth.auth_service.health;

import com.auth.auth_service.common.GlobalExceptionHandler;
import com.auth.auth_service.security.AuthEntryPoint;
import com.auth.auth_service.security.CustomUserDetailsService;
import com.auth.auth_service.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * MockMvc slice tests for HealthController.
 *
 * @WebMvcTest loads only the web layer (no JPA, no datasource).
 * GlobalExceptionHandler is imported explicitly so @RestControllerAdvice is
 * active during these tests — this is required because @WebMvcTest does not
 * scan @RestControllerAdvice classes that live outside the controller package.
 */
@WebMvcTest(HealthController.class)
@Import({GlobalExceptionHandler.class, AuthEntryPoint.class})
class HealthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    // -------------------------------------------------------------------------
    // GET /api/v1/health
    // -------------------------------------------------------------------------

    @Test
    void health_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/health")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    void health_bodySuccessIsTrue() throws Exception {
        mockMvc.perform(get("/api/v1/health")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void health_bodyMessageIsCorrect() throws Exception {
        mockMvc.perform(get("/api/v1/health")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Auth Service is up and running!"));
    }

    @Test
    void health_bodyDataIsNull() throws Exception {
        // data field should be absent or null for Void response
        mockMvc.perform(get("/api/v1/health")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    @Test
    void health_contentTypeIsJson() throws Exception {
        mockMvc.perform(get("/api/v1/health")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    // -------------------------------------------------------------------------
    // GET /api/v1/health/readiness
    // -------------------------------------------------------------------------

    @Test
    void readiness_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/health/readiness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    void readiness_bodySuccessIsTrue() throws Exception {
        mockMvc.perform(get("/api/v1/health/readiness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void readiness_bodyMessageIsCorrect() throws Exception {
        mockMvc.perform(get("/api/v1/health/readiness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Auth Service is ready to accept requests!"));
    }

    @Test
    void readiness_bodyDataIsNull() throws Exception {
        mockMvc.perform(get("/api/v1/health/readiness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    // -------------------------------------------------------------------------
    // GET /api/v1/health/liveness
    // -------------------------------------------------------------------------

    @Test
    void liveness_returns200() throws Exception {
        mockMvc.perform(get("/api/v1/health/liveness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk());
    }

    @Test
    void liveness_bodySuccessIsTrue() throws Exception {
        mockMvc.perform(get("/api/v1/health/liveness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.success").value(true));
    }

    @Test
    void liveness_bodyMessageIsCorrect() throws Exception {
        mockMvc.perform(get("/api/v1/health/liveness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message").value("Auth Service is alive!"));
    }

    @Test
    void liveness_bodyDataIsNull() throws Exception {
        mockMvc.perform(get("/api/v1/health/liveness")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    // -------------------------------------------------------------------------
    // GET /api/v1/health/exception/runtime
    // Expects the GlobalExceptionHandler to convert the thrown RuntimeException
    // -------------------------------------------------------------------------

    // @Test
    // void testRuntimeException_returns500() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(status().isInternalServerError());
    // }

    // @Test
    // void testRuntimeException_bodySuccessIsFalse() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.success").value(false));
    // }

    // @Test
    // void testRuntimeException_bodyCodeIsInternalServerError() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.code").value("INTERNAL_SERVER_ERROR"));
    // }

    // @Test
    // void testRuntimeException_bodyMessageIsUnexpectedServerError() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.message").value("Unexpected server error"));
    // }

    // @Test
    // void testRuntimeException_bodyPathIsRequestUri() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.path").value("/api/v1/health/exception/runtime"));
    // }

    // @Test
    // void testRuntimeException_bodyTimestampIsPresent() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.timestamp").isNotEmpty());
    // }

    // @Test
    // void testRuntimeException_contentTypeIsJson() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    // }

    // -------------------------------------------------------------------------
    // 404 — unknown route returns our standard ErrorResponse shape
    // -------------------------------------------------------------------------

    @Test
    void unknownRoute_returns404() throws Exception {
        mockMvc.perform(get("/api/v1/health/does-not-exist")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.code").value("NOT_FOUND"));
    }

    // -------------------------------------------------------------------------
    // 405 — method not allowed returns our standard ErrorResponse shape
    // -------------------------------------------------------------------------

    @Test
    void health_postMethod_returns405() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/v1/health")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isMethodNotAllowed())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.code").value("INTERNAL_SERVER_ERROR"));
    }
}
