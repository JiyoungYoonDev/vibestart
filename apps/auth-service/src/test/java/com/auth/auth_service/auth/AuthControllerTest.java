package com.auth.auth_service.auth;

import com.auth.auth_service.auth.dto.SignupRequest;
import com.auth.auth_service.auth.dto.SignupResponse;
import com.auth.auth_service.common.GlobalExceptionHandler;
import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.WeakPasswordException;
import com.auth.auth_service.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * MockMvc slice tests for AuthController.
 *
 * @WebMvcTest loads only the web layer (no JPA, no datasource).
 * AuthService is replaced by a Mockito stub — we test the controller's
 * HTTP contract, not the service's business logic.
 * GlobalExceptionHandler is imported explicitly so validation errors and
 * domain exceptions are translated into the standard ErrorResponse shape.
 */
@WebMvcTest(AuthController.class)
@Import(GlobalExceptionHandler.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    private static final String SIGNUP_URL = "/api/v1/auth/signup";

    /** Valid request body reused across happy-path tests. */
    private static final String VALID_BODY = """
            {"email": "user@example.com", "password": "Password1", "username": "testuser"}
            """;

    // -------------------------------------------------------------------------
    // POST /api/v1/auth/signup — Happy Path
    // -------------------------------------------------------------------------

    @Test
    void signup_validRequest_returns201() throws Exception {
        when(authService.signup(any())).thenReturn(
                new SignupResponse(UUID.randomUUID(), "user@example.com", "testuser", UserStatus.PENDING_EMAIL_VERIFICATION));

        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(status().isCreated());
    }

    @Test
    void signup_validRequest_responseBodyContainsEmail() throws Exception {
        when(authService.signup(any())).thenReturn(
                new SignupResponse(UUID.randomUUID(), "user@example.com", "testuser", UserStatus.PENDING_EMAIL_VERIFICATION));

        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(jsonPath("$.email").value("user@example.com"));
    }

    @Test
    void signup_validRequest_responseBodyContainsUsername() throws Exception {
        when(authService.signup(any())).thenReturn(
                new SignupResponse(UUID.randomUUID(), "user@example.com", "testuser", UserStatus.PENDING_EMAIL_VERIFICATION));

        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void signup_validRequest_responseBodyContainsIdAsUuid() throws Exception {
        UUID id = UUID.randomUUID();
        when(authService.signup(any())).thenReturn(
                new SignupResponse(id, "user@example.com", "testuser", UserStatus.PENDING_EMAIL_VERIFICATION));

        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(jsonPath("$.id").value(id.toString()));
    }

    @Test
    void signup_validRequest_responseBodyStatusIsPendingEmailVerification() throws Exception {
        when(authService.signup(any())).thenReturn(
                new SignupResponse(UUID.randomUUID(), "user@example.com", "testuser", UserStatus.PENDING_EMAIL_VERIFICATION));

        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_BODY))
                .andExpect(jsonPath("$.status").value("PENDING_EMAIL_VERIFICATION"));
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/auth/signup — Bean Validation (@Valid) Failures → 400
    //
    // SignupRequest constraints:
    //   email    : @NotBlank + @Email
    //   password : @NotBlank + @Size(min=8)
    //   username : @NotBlank
    // -------------------------------------------------------------------------

    @Test
    void signup_blankEmail_returns400WithValidationError() throws Exception {
        String body = """
                {"email": "", "password": "Password1", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void signup_invalidEmailFormat_returns400WithValidationError() throws Exception {
        String body = """
                {"email": "not-an-email", "password": "Password1", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void signup_blankPassword_returns400WithValidationError() throws Exception {
        String body = """
                {"email": "user@example.com", "password": "", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void signup_passwordTooShort_returns400WithValidationError() throws Exception {
        // @Size(min = 8) — 7 characters should fail
        String body = """
                {"email": "user@example.com", "password": "Pass1ab", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void signup_blankUsername_returns400WithValidationError() throws Exception {
        String body = """
                {"email": "user@example.com", "password": "Password1", "username": ""}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void signup_allFieldsMissing_returns400WithValidationError() throws Exception {
        // Empty JSON object — all @NotBlank fields will fail simultaneously
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/auth/signup — Validation error field-level details
    //
    // GlobalExceptionHandler.handleMethodArgumentNotValid()는 검증 오류를
    // Map<String, String> details 형태로 응답합니다:
    //   { "details": { "email": "Invalid email format" } }
    //
    // 메시지 문자열을 정확히 고정(계약 강제)하는 방향으로 작성합니다.
    // 메시지가 바뀌면 테스트가 깨져서 API 계약 변경을 즉시 인지할 수 있습니다.
    // -------------------------------------------------------------------------

    @Test
    void signup_invalidEmailFormat_detailsContainEmailField() throws Exception {
        String body = """
                {"email": "not-an-email", "password": "Password1", "username": "testuser"}
                """;

        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details.email").value("Invalid email format"));
    }

    @Test
    void signup_passwordTooShort_detailsContainPasswordField() throws Exception {
        String body = """
                {"email": "user@example.com", "password": "Pass1", "username": "testuser"}
                """;

        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.details.password").value("Password must be at least 8 characters long"));
    }

    // -------------------------------------------------------------------------
    // POST /api/v1/auth/signup — Domain Exceptions from AuthService
    // -------------------------------------------------------------------------

    @Test
    void signup_duplicateEmail_returns409() throws Exception {
        when(authService.signup(any())).thenThrow(new DuplicateEmailException("user@example.com"));

        String body = """
                {"email": "user@example.com", "password": "Password1", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void signup_duplicateEmail_bodyCodeIsEmailAlreadyExists() throws Exception {
        when(authService.signup(any())).thenThrow(new DuplicateEmailException("user@example.com"));

        String body = """
                {"email": "user@example.com", "password": "Password1", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(jsonPath("$.code").value("EMAIL_ALREADY_EXISTS"))
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void signup_duplicateUsername_returns409() throws Exception {
        when(authService.signup(any())).thenThrow(new DuplicateUsernameException("testuser"));

        String body = """
                {"email": "user@example.com", "password": "Password1", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isConflict());
    }

    @Test
    void signup_duplicateUsername_bodyCodeIsUsernameAlreadyExists() throws Exception {
        when(authService.signup(any())).thenThrow(new DuplicateUsernameException("testuser"));

        String body = """
                {"email": "user@example.com", "password": "Password1", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(jsonPath("$.code").value("USERNAME_ALREADY_EXISTS"))
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void signup_weakPassword_returns400() throws Exception {
        // WeakPasswordException is thrown by the service when password has no digit
        when(authService.signup(any())).thenThrow(
                new WeakPasswordException("Password must contain at least one letter and one digit"));

        String body = """
                {"email": "user@example.com", "password": "onlyletters", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest());
    }

    @Test
    void signup_weakPassword_bodyCodeIsValidationError() throws Exception {
        when(authService.signup(any())).thenThrow(
                new WeakPasswordException("Password must contain at least one letter and one digit"));

        String body = """
                {"email": "user@example.com", "password": "onlyletters", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void signup_weakPassword_detailsContainPasswordMessage() throws Exception {
        String errorMsg = "Password must contain at least one letter and one digit";
        when(authService.signup(any())).thenThrow(new WeakPasswordException(errorMsg));

        String body = """
                {"email": "user@example.com", "password": "onlyletters", "username": "testuser"}
                """;
        mockMvc.perform(post(SIGNUP_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                // GlobalExceptionHandler.handleWeakPassword() wraps as details: {"password": message}
                .andExpect(jsonPath("$.details.password").value(errorMsg));
    }

    // -------------------------------------------------------------------------
    // Wrong HTTP method — GET on a POST-only endpoint
    // Note: GlobalExceptionHandler extends ResponseEntityExceptionHandler,
    // so HttpRequestMethodNotSupportedException (405) is handled by
    // handleExceptionInternal(), which returns the correct 405 status.
    // -------------------------------------------------------------------------

    @Test
    void signup_getMethod_returns405() throws Exception {
        mockMvc.perform(get(SIGNUP_URL)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isMethodNotAllowed());
    }
}
