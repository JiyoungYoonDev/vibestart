package com.auth.auth_service.auth;

import com.auth.auth_service.auth.dto.SignupRequest;
import com.auth.auth_service.auth.dto.SignupResponse;
import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.WeakPasswordException;
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

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
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
}
