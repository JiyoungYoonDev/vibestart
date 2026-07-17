package com.auth.auth_service.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;

@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("findByEmail returns empty when user does not exist")
    void findByEmail_returnsEmpty_whenUserNotFound() {
        Optional<User> result = userRepository.findByEmail("nonexistent@example.com");

        assertThat(result).isEmpty();
    }

    @Test
    @DisplayName("findByEmail returns user when email exists")
    void findByEmail_returnsUser_whenEmailExists() {
        User user = new User("test@example.com", "$2a$12$hashedvalue", "testuser", UserRole.USER, UserStatus.ACTIVE);
        userRepository.save(user);

        Optional<User> result = userRepository.findByEmail("test@example.com");

        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("test@example.com");
        assertThat(result.get().getUsername()).isEqualTo("testuser");
        assertThat(result.get().getRole()).isEqualTo(UserRole.USER);
        assertThat(result.get().getStatus()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    @DisplayName("User entity persists all fields correctly")
    void save_persistsAllFields() {
        User user = new User("persist@example.com", "$2a$12$hash", "persistuser", UserRole.ADMIN, UserStatus.PENDING_EMAIL_VERIFICATION);
        User saved = userRepository.save(user);

        assertThat(saved.getId()).isNotNull();
        assertThat(saved.getEmail()).isEqualTo("persist@example.com");
        assertThat(saved.getPasswordHash()).isEqualTo("$2a$12$hash");
        assertThat(saved.getUsername()).isEqualTo("persistuser");
        assertThat(saved.getRole()).isEqualTo(UserRole.ADMIN);
        assertThat(saved.getStatus()).isEqualTo(UserStatus.PENDING_EMAIL_VERIFICATION);
    }

    @Test
    @DisplayName("Duplicate email throws DataIntegrityViolationException")
    void save_throwsException_whenDuplicateEmail() {
        User user1 = new User("dup@example.com", "$2a$12$hash1", "userone", UserRole.USER, UserStatus.ACTIVE);
        userRepository.saveAndFlush(user1);

        User user2 = new User("dup@example.com", "$2a$12$hash2", "usertwo", UserRole.USER, UserStatus.ACTIVE);

        assertThatThrownBy(() -> userRepository.saveAndFlush(user2))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    @DisplayName("Email is normalized to lowercase on save")
    void save_normalizesEmail_toLowercase() {
        User user = new User("Test@Example.COM", "$2a$12$hash", "mixedcase", UserRole.USER, UserStatus.ACTIVE);
        userRepository.save(user);

        Optional<User> result = userRepository.findByEmail("test@example.com");

        assertThat(result).isPresent();
        assertThat(result.get().getEmail()).isEqualTo("test@example.com");
    }
}
