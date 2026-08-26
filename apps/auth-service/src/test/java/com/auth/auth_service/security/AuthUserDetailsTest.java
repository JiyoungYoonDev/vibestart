package com.auth.auth_service.security;

import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for AuthUserDetails.
 * No Spring context — AuthUserDetails simply adapts a User entity to the
 * Spring Security UserDetails contract.
 */
class AuthUserDetailsTest {

    private User userWith(UserRole role, UserStatus status) {
        return new User("test@example.com", "hashed_password", "testuser", role, status);
    }

    // ── getAuthorities() ──────────────────────────────────────────────────────

    @Test
    void getAuthorities_returnsRoleWithPrefix_forUserRole() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.getAuthorities())
                .containsExactly(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Test
    void getAuthorities_returnsRoleWithPrefix_forAdminRole() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.ADMIN, UserStatus.ACTIVE));

        assertThat(details.getAuthorities())
                .containsExactly(new SimpleGrantedAuthority("ROLE_ADMIN"));
    }

    @Test
    void getAuthorities_returnsExactlyOneAuthority() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.getAuthorities()).hasSize(1);
    }

    // ── getUsername() — Spring Security convention: "username" is the email ──

    @Test
    void getUsername_returnsEmail() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.getUsername()).isEqualTo("test@example.com");
    }

    // ── getPassword() ──────────────────────────────────────────────────────────

    @Test
    void getPassword_returnsPasswordHash() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.getPassword()).isEqualTo("hashed_password");
    }

    // ── isEnabled() ────────────────────────────────────────────────────────────

    @Test
    void isEnabled_activeUser_returnsTrue() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    void isEnabled_pendingEmailVerificationUser_returnsTrue() {
        // Only DISABLED status should be treated as disabled
        AuthUserDetails details = new AuthUserDetails(
                userWith(UserRole.USER, UserStatus.PENDING_EMAIL_VERIFICATION));

        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    void isEnabled_disabledUser_returnsFalse() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.DISABLED));

        assertThat(details.isEnabled()).isFalse();
    }

    // ── Account state flags — hardcoded true in this implementation ──────────

    @Test
    void isAccountNonExpired_alwaysReturnsTrue() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.isAccountNonExpired()).isTrue();
    }

    @Test
    void isAccountNonLocked_alwaysReturnsTrue() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.isAccountNonLocked()).isTrue();
    }

    @Test
    void isCredentialsNonExpired_alwaysReturnsTrue() {
        AuthUserDetails details = new AuthUserDetails(userWith(UserRole.USER, UserStatus.ACTIVE));

        assertThat(details.isCredentialsNonExpired()).isTrue();
    }

    // ── getUser() ──────────────────────────────────────────────────────────────

    @Test
    void getUser_returnsOriginalEntity() {
        User user = userWith(UserRole.USER, UserStatus.ACTIVE);
        AuthUserDetails details = new AuthUserDetails(user);

        assertThat(details.getUser()).isSameAs(user);
    }
}
