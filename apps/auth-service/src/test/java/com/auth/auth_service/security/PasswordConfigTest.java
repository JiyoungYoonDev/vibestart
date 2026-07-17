package com.auth.auth_service.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class PasswordConfigTest {

    private final PasswordEncoder passwordEncoder = new PasswordConfig().passwordEncoder();

    @Test
    @DisplayName("PasswordEncoder encodes to non-null BCrypt hash")
    void encode_producesNonNullBcryptHash() {
        String hash = passwordEncoder.encode("rawpassword");

        assertThat(hash).isNotNull();
        assertThat(hash).isNotEmpty();
        assertThat(hash).startsWith("$2a$");
    }

    @Test
    @DisplayName("PasswordEncoder matches raw password against its hash")
    void matches_returnsTrue_forCorrectPassword() {
        String raw = "mySecurePassword123";
        String hash = passwordEncoder.encode(raw);

        assertThat(passwordEncoder.matches(raw, hash)).isTrue();
    }

    @Test
    @DisplayName("PasswordEncoder rejects wrong password")
    void matches_returnsFalse_forWrongPassword() {
        String hash = passwordEncoder.encode("correctPassword");

        assertThat(passwordEncoder.matches("wrongPassword", hash)).isFalse();
    }

    @Test
    @DisplayName("Encoded value is not equal to raw password")
    void encode_doesNotReturnRawPassword() {
        String raw = "plaintext";
        String hash = passwordEncoder.encode(raw);

        assertThat(hash).isNotEqualTo(raw);
    }
}
