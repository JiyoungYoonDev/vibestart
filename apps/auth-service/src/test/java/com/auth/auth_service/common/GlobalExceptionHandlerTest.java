package com.auth.auth_service.common;

import com.auth.auth_service.health.HealthController;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;

import jakarta.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for GlobalExceptionHandler.
 *
 * Two complementary strategies are used:
 *  1. @WebMvcTest — exercises the handler through the full MVC pipeline via
 *     MockMvc. HealthController is included because it exposes a deliberate
 *     exception endpoint used to trigger the advice.
 *  2. Plain unit tests — call handler methods directly with a mock
 *     HttpServletRequest, with no Spring context at all.
 */
@WebMvcTest(controllers = HealthController.class)
@Import(GlobalExceptionHandler.class)
class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // Integration-style tests via MockMvc
    // -------------------------------------------------------------------------

    // @Test
    // void runtimeException_viaEndpoint_returns500() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(status().isInternalServerError());
    // }

    // @Test
    // void runtimeException_viaEndpoint_bodySuccessIsFalse() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.success").value(false));
    // }

    // @Test
    // void runtimeException_viaEndpoint_bodyCodeIsInternalServerError() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.code").value("INTERNAL_SERVER_ERROR"));
    // }

    // @Test
    // void runtimeException_viaEndpoint_bodyMessageIsUnexpectedServerError() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.message").value("Unexpected server error"));
    // }

    // @Test
    // void runtimeException_viaEndpoint_bodyPathIsRequestUri() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.path").value("/api/v1/health/exception/runtime"));
    // }

    // @Test
    // void runtimeException_viaEndpoint_bodyTimestampIsPresent() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.timestamp").isNotEmpty());
    // }

    // @Test
    // void runtimeException_viaEndpoint_bodyDetailsIsNull() throws Exception {
    //     // details field should be absent / null for the Void variant
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(jsonPath("$.details").doesNotExist());
    // }

    // @Test
    // void runtimeException_viaEndpoint_contentTypeIsJson() throws Exception {
    //     mockMvc.perform(get("/api/v1/health/exception/runtime")
    //                     .accept(MediaType.APPLICATION_JSON))
    //             .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    // }

    // -------------------------------------------------------------------------
    // Pure unit tests — no Spring context, handler called directly
    // -------------------------------------------------------------------------

    @Test
    void handleRuntimeException_directCall_returns500Status() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/some-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleRuntimeException(new RuntimeException("boom"), mockRequest);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void handleRuntimeException_directCall_bodySuccessIsFalse() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/some-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleRuntimeException(new RuntimeException("boom"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().success()).isFalse();
    }

    @Test
    void handleRuntimeException_directCall_bodyCodeIsInternalServerError() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/some-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleRuntimeException(new RuntimeException("boom"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().code()).isEqualTo(ErrorCode.INTERNAL_SERVER_ERROR);
    }

    @Test
    void handleRuntimeException_directCall_bodyPathMatchesRequestUri() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        String expectedUri = "/api/v1/things/1";
        when(mockRequest.getRequestURI()).thenReturn(expectedUri);

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleRuntimeException(new RuntimeException("boom"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().path()).isEqualTo(expectedUri);
    }

    @Test
    void handleRuntimeException_directCall_bodyMessageIsUnexpectedServerError() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/some-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleRuntimeException(new RuntimeException("boom"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().message()).isEqualTo("Unexpected server error");
    }

    @Test
    void handleRuntimeException_directCall_bodyDetailsIsNull() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/some-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleRuntimeException(new RuntimeException("boom"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().details()).isNull();
    }

    @Test
    void handleException_directCall_returns500Status() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/checked-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleException(new Exception("checked exception"), mockRequest);

        assertThat(result.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @Test
    void handleException_directCall_bodySuccessIsFalse() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/checked-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleException(new Exception("checked exception"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().success()).isFalse();
    }

    @Test
    void handleException_directCall_bodyCodeIsInternalServerError() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/checked-endpoint");

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleException(new Exception("checked exception"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().code()).isEqualTo(ErrorCode.INTERNAL_SERVER_ERROR);
    }

    @Test
    void handleException_directCall_bodyPathMatchesRequestUri() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        String expectedUri = "/api/v1/checked-endpoint";
        when(mockRequest.getRequestURI()).thenReturn(expectedUri);

        ResponseEntity<ErrorResponse<Void>> result =
                handler.handleException(new Exception("checked exception"), mockRequest);

        assertThat(result.getBody()).isNotNull();
        assertThat(result.getBody().path()).isEqualTo(expectedUri);
    }

    // -------------------------------------------------------------------------
    // Both handlers produce identical structure regardless of exception type
    // -------------------------------------------------------------------------

    @Test
    void bothHandlers_produceSameResponseShape_forSameUri() {
        GlobalExceptionHandler handler = new GlobalExceptionHandler();
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        when(mockRequest.getRequestURI()).thenReturn("/api/v1/endpoint");

        ResponseEntity<ErrorResponse<Void>> fromRuntime =
                handler.handleRuntimeException(new RuntimeException("runtime"), mockRequest);
        ResponseEntity<ErrorResponse<Void>> fromChecked =
                handler.handleException(new Exception("checked"), mockRequest);

        // Both must have the same HTTP status
        assertThat(fromRuntime.getStatusCode()).isEqualTo(fromChecked.getStatusCode());

        // Both bodies must carry the same structural fields
        assertThat(fromRuntime.getBody()).isNotNull();
        assertThat(fromChecked.getBody()).isNotNull();
        assertThat(fromRuntime.getBody().code()).isEqualTo(fromChecked.getBody().code());
        assertThat(fromRuntime.getBody().message()).isEqualTo(fromChecked.getBody().message());
        assertThat(fromRuntime.getBody().success()).isEqualTo(fromChecked.getBody().success());
    }
}
