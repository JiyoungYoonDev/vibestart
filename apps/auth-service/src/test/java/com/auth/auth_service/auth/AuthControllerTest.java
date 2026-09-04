package com.auth.auth_service.auth;

import com.auth.auth_service.auth.dto.GoogleLoginRequest;
import com.auth.auth_service.auth.dto.LoginRequest;
import com.auth.auth_service.auth.dto.LoginResponse;
import com.auth.auth_service.auth.dto.SignupRequest;
import com.auth.auth_service.auth.dto.SignupResponse;
import com.auth.auth_service.common.GlobalExceptionHandler;
import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.InvalidCredentialsException;
import com.auth.auth_service.exception.InvalidGoogleTokenException;
import com.auth.auth_service.exception.PasswordChangeNotAllowedException;
import com.auth.auth_service.exception.WeakPasswordException;
import com.auth.auth_service.security.AuthEntryPoint;
import com.auth.auth_service.security.AuthUserDetails;
import com.auth.auth_service.security.CustomUserDetailsService;
import com.auth.auth_service.security.JwtService;
import com.auth.auth_service.security.SecurityConfig;
import com.auth.auth_service.security.TokenBlacklistService;
import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
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
 *
 * SecurityConfig is imported explicitly (kept active — NOT disabled via
 * addFilters=false — so authenticated endpoints like /me and /logout can be
 * tested realistically). @WebMvcTest does NOT pick up a plain @Configuration
 * like SecurityConfig automatically (it isn't one of its scanned component
 * types) — omitting this import let every request reach the controller
 * regardless of auth state, silently no-op'ing every unauthenticated-request
 * test until this was added.
 *
 * @WebMvcTest still auto-detects JwtAuthFilter on its own too, since it's a
 * Filter @Component — but SecurityConfig now registers a disabled
 * FilterRegistrationBean<JwtAuthFilter> specifically to stop Spring Boot from
 * ALSO auto-registering it as a standalone servlet filter outside Spring
 * Security's own chain (see that bean's own comment for what broke without
 * it: a validly-authenticated request still got treated as anonymous).
 * JwtAuthFilter's own dependencies (JwtService, CustomUserDetailsService,
 * TokenBlacklistService) are not web-layer beans, so they are replaced with
 * Mockito stubs. AuthEntryPoint is imported explicitly so the real 401 JSON
 * response logic stays active.
 *
 * RateLimitFilter is disabled here for the same reason (auto-detected as a
 * Filter @Component, same as JwtAuthFilter) — this class's shared
 * ApplicationContext calls /signup and /login far more than their per-hour
 * and per-minute budgets across its ~50 @Test methods, so without this the
 * later tests in the class start failing on unrelated assertions once the
 * bucket for that endpoint runs dry.
 */
@WebMvcTest(AuthController.class)
@Import({GlobalExceptionHandler.class, AuthEntryPoint.class, SecurityConfig.class})
@TestPropertySource(properties = "rate-limit.enabled=false")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

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
    // -------------------------------------------------------------------------

    @Test
    void signup_getMethod_returns405() throws Exception {
        mockMvc.perform(get(SIGNUP_URL)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isMethodNotAllowed());
    }

    // =========================================================================
    // POST /api/v1/auth/login
    // =========================================================================

    private static final String LOGIN_URL = "/api/v1/auth/login";

    /** Valid login body reused across happy-path tests. */
    private static final String VALID_LOGIN_BODY = """
            {"email": "user@example.com", "password": "Password1"}
            """;

    // ── Happy Path ────────────────────────────────────────────────────────────

    @Test
    void login_validRequest_returns200() throws Exception {
        when(authService.login(any(LoginRequest.class))).thenReturn(
                new LoginResponse("header.payload.sig", "Bearer", 3600L));

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_LOGIN_BODY))
                .andExpect(status().isOk());
    }

    @Test
    void login_validRequest_responseBodyContainsAccessToken() throws Exception {
        when(authService.login(any())).thenReturn(
                new LoginResponse("header.payload.sig", "Bearer", 3600L));

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_LOGIN_BODY))
                .andExpect(jsonPath("$.accessToken").value("header.payload.sig"));
    }

    @Test
    void login_validRequest_responseBodyTokenTypeIsBearer() throws Exception {
        when(authService.login(any())).thenReturn(
                new LoginResponse("header.payload.sig", "Bearer", 3600L));

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_LOGIN_BODY))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void login_validRequest_responseBodyContainsExpiresIn() throws Exception {
        when(authService.login(any())).thenReturn(
                new LoginResponse("header.payload.sig", "Bearer", 3600L));

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_LOGIN_BODY))
                .andExpect(jsonPath("$.expiresIn").value(3600));
    }

    // ── Bean Validation (@Valid) Failures → 400 ───────────────────────────────

    @Test
    void login_blankEmail_returns400WithValidationError() throws Exception {
        String body = """
                {"email": "", "password": "Password1"}
                """;
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void login_invalidEmailFormat_returns400WithValidationError() throws Exception {
        String body = """
                {"email": "not-an-email", "password": "Password1"}
                """;
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details.email").value("Invalid email format"));
    }

    @Test
    void login_blankPassword_returns400WithValidationError() throws Exception {
        String body = """
                {"email": "user@example.com", "password": ""}
                """;
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"))
                .andExpect(jsonPath("$.details.password").value("Password is required"));
    }

    // ── Domain Exception: InvalidCredentialsException ─────────────────────────
    //
    // In the @WebMvcTest slice, Spring Security's filter chain converts the
    // unhandled RuntimeException into a 401. A dedicated
    // @ExceptionHandler(InvalidCredentialsException.class) returning 401
    // with code INVALID_CREDENTIALS should be added to GlobalExceptionHandler
    // to make this behaviour explicit and consistent in production.
    // -------------------------------------------------------------------------

    @Test
    void login_invalidCredentials_returns401() throws Exception {
        when(authService.login(any())).thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_LOGIN_BODY))
                .andExpect(status().isUnauthorized());
    }

    /**
     * [TDD — RED] This test requires a dedicated @ExceptionHandler in GlobalExceptionHandler:
     *
     *   @ExceptionHandler(InvalidCredentialsException.class)
     *   public ResponseEntity<ErrorResponse<Void>> handleInvalidCredentials(
     *           InvalidCredentialsException ex, HttpServletRequest request) {
     *       ErrorResponse<Void> body = ErrorResponse.of(
     *               ErrorCode.INVALID_CREDENTIALS,
     *               "Invalid credentials",
     *               request.getRequestURI());
     *       return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
     *   }
     *
     * Without this handler, Spring Security intercepts the exception and returns
     * 401 with no JSON body — so $.code and $.success cannot be asserted.
     */
    @Test
    void login_invalidCredentials_codeIsInvalidCredentials() throws Exception {
        when(authService.login(any())).thenThrow(new InvalidCredentialsException());

        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(VALID_LOGIN_BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.success").value(false));
    }

    // ── Wrong HTTP method ─────────────────────────────────────────────────────

    @Test
    void login_getMethod_returns405() throws Exception {
        mockMvc.perform(get(LOGIN_URL)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isMethodNotAllowed());
    }

    // =========================================================================
    // POST /api/v1/auth/google
    // =========================================================================

    private static final String GOOGLE_URL = "/api/v1/auth/google";

    @Test
    void loginWithGoogle_validToken_returns200() throws Exception {
        when(authService.loginWithGoogle(any())).thenReturn(
                new LoginResponse("header.payload.sig", "Bearer", 3600L));

        mockMvc.perform(post(GOOGLE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"idToken": "google-id-token"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("header.payload.sig"));
    }

    @Test
    void loginWithGoogle_blankIdToken_returns400WithValidationError() throws Exception {
        mockMvc.perform(post(GOOGLE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"idToken": ""}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void loginWithGoogle_invalidToken_returns401() throws Exception {
        when(authService.loginWithGoogle(any()))
                .thenThrow(new InvalidGoogleTokenException("Google rejected the sign-in token"));

        mockMvc.perform(post(GOOGLE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"idToken": "bad-token"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_GOOGLE_TOKEN"));
    }

    // =========================================================================
    // GET /api/v1/auth/me
    //
    // Exercises the real JwtAuthFilter + SecurityConfig (not disabled in this
    // slice — see the class doc comment), with JwtService/CustomUserDetailsService
    // mocked so no real token needs to be signed. "valid.jwt.token" is an
    // opaque string here; it's never actually parsed since jwtService itself
    // is a Mockito stub.
    // =========================================================================

    private static final String ME_URL = "/api/v1/auth/me";
    private static final String VALID_TOKEN = "valid.jwt.token";

    private User stubUser() {
        User user = new User("user@example.com", "hashed", "testuser", UserRole.USER, UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user, "id", UUID.fromString("00000000-0000-0000-0000-000000000001"));
        return user;
    }

    /** Wires jwtService + customUserDetailsService so VALID_TOKEN authenticates as `user`. */
    private void stubAuthenticatedRequest(User user) {
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
        when(jwtService.extractJti(VALID_TOKEN)).thenReturn("jti-1");
        when(tokenBlacklistService.isBlacklisted("jti-1")).thenReturn(false);
        when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(user.getId().toString());
        when(customUserDetailsService.loadUserByUsername(user.getId().toString()))
                .thenReturn(new AuthUserDetails(user));
    }

    @Test
    void me_noAuthorizationHeader_returns401() throws Exception {
        mockMvc.perform(get(ME_URL))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void me_noAuthorizationHeader_bodyCodeIsUnauthorized() throws Exception {
        mockMvc.perform(get(ME_URL))
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    void me_blacklistedToken_returns401() throws Exception {
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
        when(jwtService.extractJti(VALID_TOKEN)).thenReturn("jti-1");
        when(tokenBlacklistService.isBlacklisted("jti-1")).thenReturn(true);

        mockMvc.perform(get(ME_URL).header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void me_validToken_returns200() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(get(ME_URL).header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(status().isOk());
    }

    @Test
    void me_validToken_responseBodyContainsEmail() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(get(ME_URL).header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(jsonPath("$.email").value("user@example.com"));
    }

    @Test
    void me_validToken_responseBodyContainsUsername() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(get(ME_URL).header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    // =========================================================================
    // POST /api/v1/auth/logout
    // =========================================================================

    private static final String LOGOUT_URL = "/api/v1/auth/logout";

    @Test
    void logout_noAuthorizationHeader_returns401() throws Exception {
        mockMvc.perform(post(LOGOUT_URL))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logout_validToken_returns204() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(post(LOGOUT_URL).header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(status().isNoContent());
    }

    @Test
    void logout_validToken_callsAuthServiceWithTheBareToken() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(post(LOGOUT_URL).header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(status().isNoContent());

        // Controller strips the "Bearer " prefix before handing off to the service
        verify(authService).logout(VALID_TOKEN);
    }

    // =========================================================================
    // PATCH /api/v1/auth/me
    // =========================================================================

    private static final String UPDATE_ME_BODY = """
            {"username": "newname"}
            """;

    @Test
    void updateMe_noAuthorizationHeader_returns401() throws Exception {
        mockMvc.perform(patch(ME_URL).contentType(MediaType.APPLICATION_JSON).content(UPDATE_ME_BODY))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void updateMe_validToken_returns200WithUpdatedUsername() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);
        User updated = stubUser();
        updated.setUsername("newname");
        when(authService.updateUsername(any(User.class), eq("newname"))).thenReturn(updated);

        mockMvc.perform(patch(ME_URL).header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content(UPDATE_ME_BODY))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("newname"));
    }

    @Test
    void updateMe_blankUsername_returns400WithValidationError() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(patch(ME_URL).header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content("""
                                {"username": ""}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void updateMe_usernameTakenByAnotherAccount_returns409() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);
        when(authService.updateUsername(any(User.class), eq("taken")))
                .thenThrow(new DuplicateUsernameException("taken"));

        mockMvc.perform(patch(ME_URL).header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content("""
                                {"username": "taken"}
                                """))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("USERNAME_ALREADY_EXISTS"));
    }

    // =========================================================================
    // POST /api/v1/auth/change-password
    // =========================================================================

    private static final String CHANGE_PASSWORD_URL = "/api/v1/auth/change-password";

    private static final String VALID_CHANGE_PASSWORD_BODY = """
            {"currentPassword": "OldPass1", "newPassword": "NewPass2"}
            """;

    @Test
    void changePassword_noAuthorizationHeader_returns401() throws Exception {
        mockMvc.perform(post(CHANGE_PASSWORD_URL)
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_CHANGE_PASSWORD_BODY))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void changePassword_validToken_returns204() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(post(CHANGE_PASSWORD_URL).header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_CHANGE_PASSWORD_BODY))
                .andExpect(status().isNoContent());
    }

    @Test
    void changePassword_wrongCurrentPassword_returns401WithInvalidCredentials() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);
        org.mockito.Mockito.doThrow(new InvalidCredentialsException())
                .when(authService).changePassword(any(User.class), any());

        mockMvc.perform(post(CHANGE_PASSWORD_URL).header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_CHANGE_PASSWORD_BODY))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
    }

    @Test
    void changePassword_weakNewPassword_returns400WithValidationError() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);

        mockMvc.perform(post(CHANGE_PASSWORD_URL).header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content("""
                                {"currentPassword": "OldPass1", "newPassword": "short"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_ERROR"));
    }

    @Test
    void changePassword_googleOnlyAccount_returns400() throws Exception {
        User user = stubUser();
        stubAuthenticatedRequest(user);
        org.mockito.Mockito.doThrow(new PasswordChangeNotAllowedException(
                        "This account signed in with Google and has no password to change."))
                .when(authService).changePassword(any(User.class), any());

        mockMvc.perform(post(CHANGE_PASSWORD_URL).header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content(VALID_CHANGE_PASSWORD_BODY))
                .andExpect(status().isBadRequest());
    }
}
