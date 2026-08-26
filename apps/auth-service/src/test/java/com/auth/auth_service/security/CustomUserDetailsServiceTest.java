package com.auth.auth_service.security;

import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRepository;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

/**
 * Pure unit tests for CustomUserDetailsService.
 * No Spring context — MockitoExtension wires a mocked UserRepository directly.
 */
@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private CustomUserDetailsService customUserDetailsService;

    private User userWithId(UUID id) {
        User user = new User("test@example.com", "hashed_password", "testuser", UserRole.USER, UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }

    // ── Happy path ────────────────────────────────────────────────────────────

    @Test
    void loadUserByUsername_existingUser_returnsAuthUserDetails() {
        UUID userId = UUID.randomUUID();
        User user = userWithId(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        AuthUserDetails result = customUserDetailsService.loadUserByUsername(userId.toString());

        assertThat(result).isNotNull();
    }

    @Test
    void loadUserByUsername_existingUser_wrapsTheFoundUser() {
        UUID userId = UUID.randomUUID();
        User user = userWithId(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        AuthUserDetails result = customUserDetailsService.loadUserByUsername(userId.toString());

        assertThat(result.getUser()).isSameAs(user);
    }

    @Test
    void loadUserByUsername_existingUser_usernameIsUserEmail() {
        UUID userId = UUID.randomUUID();
        User user = userWithId(userId);
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));

        AuthUserDetails result = customUserDetailsService.loadUserByUsername(userId.toString());

        assertThat(result.getUsername()).isEqualTo("test@example.com");
    }

    // ── User not found ────────────────────────────────────────────────────────

    @Test
    void loadUserByUsername_nonExistingUser_throwsUsernameNotFoundException() {
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(userId.toString()))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void loadUserByUsername_nonExistingUser_exceptionMessageContainsUserId() {
        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(userId.toString()))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining(userId.toString());
    }

    // ── Invalid UUID string ───────────────────────────────────────────────────
    //
    // CustomUserDetailsService.loadUserByUsername() calls UUID.fromString(userId)
    // before touching the repository. An invalid UUID string throws
    // IllegalArgumentException — it is never wrapped into UsernameNotFoundException.

    @Test
    void loadUserByUsername_invalidUuid_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername("not-a-valid-uuid"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void loadUserByUsername_invalidUuid_returnsBeforeQueryingRepository() {
        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername("not-a-valid-uuid"))
                .isInstanceOf(IllegalArgumentException.class);

        org.mockito.Mockito.verifyNoInteractions(userRepository);
    }

    @Test
    void loadUserByUsername_blankString_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> customUserDetailsService.loadUserByUsername(""))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
