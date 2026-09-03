package com.auth.auth_service.auth;

import com.auth.auth_service.auth.dto.GoogleLoginRequest;
import com.auth.auth_service.auth.dto.LoginRequest;
import com.auth.auth_service.auth.dto.LoginResponse;
import com.auth.auth_service.auth.dto.SignupRequest;
import com.auth.auth_service.auth.dto.SignupResponse;
import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.InvalidCredentialsException;
import com.auth.auth_service.exception.InvalidGoogleTokenException;
import com.auth.auth_service.exception.WeakPasswordException;
import com.auth.auth_service.security.GoogleTokenVerifier;
import com.auth.auth_service.security.GoogleUserInfo;
import com.auth.auth_service.security.JwtProperties;
import com.auth.auth_service.security.JwtService;
import com.auth.auth_service.security.TokenBlacklistService;
import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRepository;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.util.Date;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Pure unit tests for AuthService.
 * No Spring context — MockitoExtension wires mocks directly.
 * @Transactional on AuthService is ignored here; transactional
 * behaviour is covered by integration tests.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtService jwtService;

    @Mock
    private JwtProperties jwtProperties;

    @Mock
    private TokenBlacklistService tokenBlacklistService;

    @Mock
    private GoogleTokenVerifier googleTokenVerifier;

    @InjectMocks
    private AuthService authService;

    // ── helpers ──────────────────────────────────────────────────────────────

    /** Stubs the repository to report no existing email or username. */
    private void noExistingUsers() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
    }

    /** Creates a minimal persisted-looking User for duplicate stubs. */
    private User existingUser() {
        return new User("taken@example.com", "hash", "taken", UserRole.USER, UserStatus.ACTIVE);
    }

    /** Creates a typical active user for login scenarios. */
    private User activeUser() {
        return new User("user@example.com", "hashed_password", "testuser", UserRole.USER, UserStatus.ACTIVE);
    }

    // ── Happy Path ────────────────────────────────────────────────────────────

    @Test
    void signup_validRequest_responseEmailMatchesRequest() {
        noExistingUsers();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");

        SignupResponse response = authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser"));

        assertThat(response.email()).isEqualTo("user@example.com");
    }

    @Test
    void signup_validRequest_responseUsernameMatchesRequest() {
        noExistingUsers();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");

        SignupResponse response = authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser"));

        assertThat(response.username()).isEqualTo("testuser");
    }

    @Test
    void signup_validRequest_responseStatusIsPendingEmailVerification() {
        noExistingUsers();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");

        SignupResponse response = authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser"));

        assertThat(response.status()).isEqualTo(UserStatus.PENDING_EMAIL_VERIFICATION);
    }

    @Test
    void signup_validRequest_userIsPersisted() {
        noExistingUsers();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");

        authService.signup(new SignupRequest("user@example.com", "Password1", "testuser"));

        verify(userRepository, times(1)).save(any(User.class));
    }

    // ── Password encoding ─────────────────────────────────────────────────────

    @Test
    void signup_validRequest_rawPasswordIsPassedToEncoder() {
        noExistingUsers();
        when(passwordEncoder.encode("Password1")).thenReturn("$2a$bcrypt_hash");

        authService.signup(new SignupRequest("user@example.com", "Password1", "testuser"));

        // The exact raw password must reach the encoder — never a pre-hashed value
        verify(passwordEncoder).encode("Password1");
    }

    @Test
    void signup_validRequest_hashedPasswordIsStoredNotRaw() {
        noExistingUsers();
        when(passwordEncoder.encode(anyString())).thenReturn("$2a$bcrypt_hash");
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);

        authService.signup(new SignupRequest("user@example.com", "Password1", "testuser"));

        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getPasswordHash())
                .isEqualTo("$2a$bcrypt_hash")
                .isNotEqualTo("Password1");
    }

    // ── Email normalisation ───────────────────────────────────────────────────

    @Test
    void signup_upperCaseEmail_isStoredAsLowerCase() {
        // User.setEmail() normalises to lowercase — verify this reaches the DB layer
        noExistingUsers();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);

        authService.signup(new SignupRequest("User@EXAMPLE.COM", "Password1", "testuser"));

        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo("user@example.com");
    }

    // ── Duplicate email ───────────────────────────────────────────────────────

    @Test
    void signup_duplicateEmail_throwsDuplicateEmailException() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(existingUser()));

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser")))
                .isInstanceOf(DuplicateEmailException.class);
    }

    @Test
    void signup_duplicateEmail_exceptionCarriesEmail() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(existingUser()));

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser")))
                .isInstanceOf(DuplicateEmailException.class)
                .satisfies(ex -> assertThat(((DuplicateEmailException) ex).getEmail())
                        .isEqualTo("user@example.com"));
    }

    @Test
    void signup_duplicateEmail_saveIsNeverCalled() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(existingUser()));

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser")))
                .isInstanceOf(DuplicateEmailException.class);

        verify(userRepository, never()).save(any());
    }

    // ── Duplicate username ────────────────────────────────────────────────────

    @Test
    void signup_duplicateUsername_throwsDuplicateUsernameException() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(existingUser()));

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser")))
                .isInstanceOf(DuplicateUsernameException.class);
    }

    @Test
    void signup_duplicateUsername_exceptionCarriesUsername() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());
        when(userRepository.findByUsername("testuser")).thenReturn(Optional.of(existingUser()));

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser")))
                .isInstanceOf(DuplicateUsernameException.class)
                .satisfies(ex -> assertThat(((DuplicateUsernameException) ex).getUsername())
                        .isEqualTo("testuser"));
    }

    // ── Validation order: email check runs before username check ──────────────

    @Test
    void signup_duplicateEmailAndUsername_emailCheckTakesPrecedence() {
        // Both collide — the service must throw for email, never reaching username.
        // findByUsername stub is lenient: it documents the scenario (both exist)
        // but is intentionally never reached.
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.of(existingUser()));
        lenient().when(userRepository.findByUsername(anyString())).thenReturn(Optional.of(existingUser()));

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser")))
                .isInstanceOf(DuplicateEmailException.class);

        verify(userRepository, never()).findByUsername(anyString());
    }

    // ── Password strength: must contain at least one letter AND one digit ─────

    @Test
    void signup_passwordAllLetters_throwsWeakPasswordException() {
        noExistingUsers();

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "onlyletters", "testuser")))
                .isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void signup_passwordAllDigits_throwsWeakPasswordException() {
        noExistingUsers();

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "12345678", "testuser")))
                .isInstanceOf(WeakPasswordException.class);
    }

    @Test
    void signup_passwordWithLetterAndDigit_doesNotThrow() {
        noExistingUsers();
        when(passwordEncoder.encode(anyString())).thenReturn("hashed");

        assertThatCode(() -> authService.signup(
                new SignupRequest("user@example.com", "Password1", "testuser")))
                .doesNotThrowAnyException();
    }

    @Test
    void signup_weakPassword_saveIsNeverCalled() {
        noExistingUsers();

        assertThatThrownBy(() -> authService.signup(
                new SignupRequest("user@example.com", "onlyletters", "testuser")))
                .isInstanceOf(WeakPasswordException.class);

        verify(userRepository, never()).save(any());
    }

    // =========================================================================
    // login()
    // =========================================================================

    // ── Happy Path ────────────────────────────────────────────────────────────

    @Test
    void login_validCredentials_returnsAccessToken() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(activeUser()));
        when(passwordEncoder.matches("Password1", "hashed_password")).thenReturn(true);
        when(jwtService.generateToken(any())).thenReturn("header.payload.signature");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        LoginResponse response = authService.login(new LoginRequest("user@example.com", "Password1"));

        assertThat(response.accessToken()).isEqualTo("header.payload.signature");
    }

    @Test
    void login_validCredentials_tokenTypeIsBearer() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(activeUser()));
        when(passwordEncoder.matches("Password1", "hashed_password")).thenReturn(true);
        when(jwtService.generateToken(any())).thenReturn("header.payload.signature");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        LoginResponse response = authService.login(new LoginRequest("user@example.com", "Password1"));

        assertThat(response.tokenType()).isEqualTo("Bearer");
    }

    @Test
    void login_validCredentials_expiresInIsSeconds() {
        // 900_000ms → 900s (ms / 1000 = seconds)
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(activeUser()));
        when(passwordEncoder.matches("Password1", "hashed_password")).thenReturn(true);
        when(jwtService.generateToken(any())).thenReturn("mock.jwt.token");
        when(jwtProperties.expirationMs()).thenReturn(900_000L);

        LoginResponse response = authService.login(new LoginRequest("user@example.com", "Password1"));

        assertThat(response.expiresIn()).isEqualTo(900L);
    }

    @Test
    void login_validCredentials_jwtServiceReceivesTheFoundUser() {
        User user = activeUser();
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(jwtService.generateToken(any())).thenReturn("token");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        authService.login(new LoginRequest("user@example.com", "Password1"));

        // The exact User object from the repository must be forwarded to jwtService
        verify(jwtService).generateToken(user);
    }

    // ── Email normalisation ───────────────────────────────────────────────────

    @Test
    void login_upperCaseEmail_isNormalizedBeforeLookup() {
        // login() calls email.toLowerCase() before querying the repository
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(activeUser()));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);
        when(jwtService.generateToken(any())).thenReturn("token");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        authService.login(new LoginRequest("USER@EXAMPLE.COM", "Password1"));

        verify(userRepository).findByEmail("user@example.com");
    }

    // ── Status: PENDING_EMAIL_VERIFICATION is allowed ─────────────────────────

    @Test
    void login_pendingEmailVerification_returnsLoginResponse() {
        User pendingUser = new User("user@example.com", "hashed_password", "testuser",
                UserRole.USER, UserStatus.PENDING_EMAIL_VERIFICATION);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(pendingUser));
        when(passwordEncoder.matches("Password1", "hashed_password")).thenReturn(true);
        when(jwtService.generateToken(any())).thenReturn("token");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        // PENDING_EMAIL_VERIFICATION is not DISABLED — login must succeed
        assertThatCode(() -> authService.login(new LoginRequest("user@example.com", "Password1")))
                .doesNotThrowAnyException();
    }

    // ── Error: email not found ────────────────────────────────────────────────

    @Test
    void login_emailNotFound_throwsInvalidCredentialsException() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("unknown@example.com", "Password1")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_emailNotFound_jwtServiceIsNeverCalled() {
        when(userRepository.findByEmail(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> authService.login(new LoginRequest("unknown@example.com", "Password1")))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(jwtService, never()).generateToken(any());
    }

    // ── Error: wrong password ─────────────────────────────────────────────────

    @Test
    void login_wrongPassword_throwsInvalidCredentialsException() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(activeUser()));
        when(passwordEncoder.matches("WrongPass1", "hashed_password")).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("user@example.com", "WrongPass1")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_wrongPassword_jwtServiceIsNeverCalled() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(activeUser()));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> authService.login(new LoginRequest("user@example.com", "WrongPass1")))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(jwtService, never()).generateToken(any());
    }

    // ── Error: disabled user ──────────────────────────────────────────────────

    @Test
    void login_disabledUser_throwsInvalidCredentialsException() {
        User disabledUser = new User("user@example.com", "hashed_password", "testuser",
                UserRole.USER, UserStatus.DISABLED);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(disabledUser));
        when(passwordEncoder.matches("Password1", "hashed_password")).thenReturn(true);

        assertThatThrownBy(() -> authService.login(new LoginRequest("user@example.com", "Password1")))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void login_disabledUser_jwtServiceIsNeverCalled() {
        User disabledUser = new User("user@example.com", "hashed_password", "testuser",
                UserRole.USER, UserStatus.DISABLED);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(disabledUser));
        when(passwordEncoder.matches(anyString(), anyString())).thenReturn(true);

        assertThatThrownBy(() -> authService.login(new LoginRequest("user@example.com", "Password1")))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(jwtService, never()).generateToken(any());
    }

    // =========================================================================
    // loginWithGoogle()
    // =========================================================================

    @Test
    void loginWithGoogle_newGoogleUser_createsAndPersistsUser() {
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleUserInfo("g-sub-1", "newperson@example.com", true, "New Person"));
        when(userRepository.findByGoogleId("g-sub-1")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("newperson@example.com")).thenReturn(Optional.empty());
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(jwtService.generateToken(any())).thenReturn("token");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        LoginResponse response = authService.loginWithGoogle(new GoogleLoginRequest("google-id-token"));

        assertThat(response.accessToken()).isEqualTo("token");
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getEmail()).isEqualTo("newperson@example.com");
        assertThat(captor.getValue().getGoogleId()).isEqualTo("g-sub-1");
        assertThat(captor.getValue().getPasswordHash()).isNull();
    }

    @Test
    void loginWithGoogle_existingGoogleUser_reusesAccountWithoutSaving() {
        User existing = User.forGoogleSignIn("returning@example.com", "returning", "g-sub-2");
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleUserInfo("g-sub-2", "returning@example.com", true, "Returning Person"));
        when(userRepository.findByGoogleId("g-sub-2")).thenReturn(Optional.of(existing));
        when(jwtService.generateToken(existing)).thenReturn("token");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        authService.loginWithGoogle(new GoogleLoginRequest("google-id-token"));

        verify(userRepository, never()).save(any());
    }

    @Test
    void loginWithGoogle_emailMatchesExistingPasswordAccount_linksGoogleId() {
        User existingPasswordUser = activeUser();
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleUserInfo("g-sub-3", "user@example.com", true, "Existing User"));
        when(userRepository.findByGoogleId("g-sub-3")).thenReturn(Optional.empty());
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(existingPasswordUser));
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
        when(jwtService.generateToken(any())).thenReturn("token");
        when(jwtProperties.expirationMs()).thenReturn(3_600_000L);

        authService.loginWithGoogle(new GoogleLoginRequest("google-id-token"));

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(captor.capture());
        assertThat(captor.getValue().getGoogleId()).isEqualTo("g-sub-3");
    }

    @Test
    void loginWithGoogle_invalidToken_propagatesInvalidGoogleTokenException() {
        when(googleTokenVerifier.verify("bad-token"))
                .thenThrow(new InvalidGoogleTokenException("Google rejected the sign-in token"));

        assertThatThrownBy(() -> authService.loginWithGoogle(new GoogleLoginRequest("bad-token")))
                .isInstanceOf(InvalidGoogleTokenException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void loginWithGoogle_disabledUser_throwsInvalidCredentialsException() {
        User disabled = User.forGoogleSignIn("disabled@example.com", "disabled", "g-sub-4");
        disabled.setStatus(UserStatus.DISABLED);
        when(googleTokenVerifier.verify("google-id-token"))
                .thenReturn(new GoogleUserInfo("g-sub-4", "disabled@example.com", true, "Disabled User"));
        when(userRepository.findByGoogleId("g-sub-4")).thenReturn(Optional.of(disabled));

        assertThatThrownBy(() -> authService.loginWithGoogle(new GoogleLoginRequest("google-id-token")))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(jwtService, never()).generateToken(any());
    }

    // =========================================================================
    // logout()
    // =========================================================================

    @Test
    void logout_revokesTheTokensJti() {
        String token = "header.payload.sig";
        when(jwtService.extractJti(token)).thenReturn("jti-123");
        when(jwtService.extractExpiration(token)).thenReturn(new Date(System.currentTimeMillis() + 60_000));

        authService.logout(token);

        verify(tokenBlacklistService).blacklist(eq("jti-123"), any(Duration.class));
    }

    @Test
    void logout_ttlPassedToBlacklistIsRoughlyTheTokensRemainingLifetime() {
        String token = "header.payload.sig";
        when(jwtService.extractJti(token)).thenReturn("jti-123");
        when(jwtService.extractExpiration(token)).thenReturn(new Date(System.currentTimeMillis() + 60_000));

        authService.logout(token);

        ArgumentCaptor<Duration> ttlCaptor = ArgumentCaptor.forClass(Duration.class);
        verify(tokenBlacklistService).blacklist(eq("jti-123"), ttlCaptor.capture());
        // Allow a few seconds of test-execution slack around the expected ~60s
        assertThat(ttlCaptor.getValue().toSeconds()).isBetween(55L, 60L);
    }
}
