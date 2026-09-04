package com.auth.auth_service.auth;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.PasswordChangeNotAllowedException;
import com.auth.auth_service.exception.WeakPasswordException;
import com.auth.auth_service.security.GoogleTokenVerifier;
import com.auth.auth_service.security.GoogleUserInfo;
import com.auth.auth_service.security.JwtProperties;
import com.auth.auth_service.security.JwtService;
import com.auth.auth_service.security.TokenBlacklistService;
import com.auth.auth_service.exception.InvalidCredentialsException;
import com.auth.auth_service.auth.dto.ChangePasswordRequest;
import com.auth.auth_service.auth.dto.GoogleLoginRequest;
import com.auth.auth_service.auth.dto.LoginRequest;
import com.auth.auth_service.auth.dto.LoginResponse;
import com.auth.auth_service.auth.dto.SignupRequest;
import com.auth.auth_service.auth.dto.SignupResponse;
import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRepository;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;

import java.time.Duration;
import java.time.Instant;

@Service
@Transactional
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final TokenBlacklistService tokenBlacklistService;
    private final GoogleTokenVerifier googleTokenVerifier;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, JwtProperties jwtProperties, TokenBlacklistService tokenBlacklistService, GoogleTokenVerifier googleTokenVerifier) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.tokenBlacklistService = tokenBlacklistService;
        this.googleTokenVerifier = googleTokenVerifier;
    }

    public SignupResponse signup(SignupRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new DuplicateEmailException(request.email());
        }

        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new DuplicateUsernameException(request.username());
        }

        validatePasswordStrength(request.password());

        // bcryt
        String hashedPassword = passwordEncoder.encode(request.password());
        
        User newUser = new User(request.email(), hashedPassword, request.username(), UserRole.USER, UserStatus.PENDING_EMAIL_VERIFICATION);
        userRepository.save(newUser);
        return new SignupResponse(newUser.getId(), newUser.getEmail(), newUser.getUsername(), newUser.getStatus());
    }

    @Transactional(readOnly = true)
    public LoginResponse login(LoginRequest request) {
        String email = request.email().toLowerCase();
        User user = userRepository.findByEmail(email)
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }

        if (user.getStatus() == UserStatus.DISABLED) {
            throw new InvalidCredentialsException();
        }

        String token = jwtService.generateToken(user);
        long expiresInSeconds = jwtProperties.expirationMs() / 1000;

        return new LoginResponse(token, "Bearer", expiresInSeconds);
    }

    public LoginResponse loginWithGoogle(GoogleLoginRequest request) {
        GoogleUserInfo googleUser = googleTokenVerifier.verify(request.idToken());

        User user = userRepository.findByGoogleId(googleUser.googleId())
                .orElseGet(() -> userRepository.findByEmail(googleUser.email())
                        .map(existing -> linkGoogleId(existing, googleUser.googleId()))
                        .orElseGet(() -> userRepository.save(User.forGoogleSignIn(
                                googleUser.email(), generateUsername(googleUser), googleUser.googleId()))));

        if (user.getStatus() == UserStatus.DISABLED) {
            throw new InvalidCredentialsException();
        }

        String token = jwtService.generateToken(user);
        long expiresInSeconds = jwtProperties.expirationMs() / 1000;
        return new LoginResponse(token, "Bearer", expiresInSeconds);
    }

    private User linkGoogleId(User existing, String googleId) {
        existing.setGoogleId(googleId);
        return userRepository.save(existing);
    }

    private String generateUsername(GoogleUserInfo googleUser) {
        String base = (googleUser.name() != null && !googleUser.name().isBlank())
                ? googleUser.name().replaceAll("\\s+", "")
                : googleUser.email().substring(0, googleUser.email().indexOf('@'));
        String candidate = base;
        int suffix = 1;
        while (userRepository.findByUsername(candidate).isPresent()) {
            candidate = base + suffix++;
        }
        return candidate;
    }

    /**
     * JWTs are stateless, so "logging out" can't invalidate the token
     * itself — it revokes this one token's jti in TokenBlacklistService
     * (Redis, TTL'd to the token's own remaining lifetime) so JwtAuthFilter
     * rejects it on any later request, even though the signature and
     * expiry still check out.
     */
    public void logout(String token) {
        String jti = jwtService.extractJti(token);
        Instant expiresAt = jwtService.extractExpiration(token).toInstant();
        Duration remaining = Duration.between(Instant.now(), expiresAt);
        tokenBlacklistService.blacklist(jti, remaining);
    }

    public User updateUsername(User user, String newUsername) {
        if (!newUsername.equals(user.getUsername()) && userRepository.findByUsername(newUsername).isPresent()) {
            throw new DuplicateUsernameException(newUsername);
        }
        user.setUsername(newUsername);
        return userRepository.save(user);
    }

    /**
     * Google-only accounts (signed up via forGoogleSignIn) have no
     * passwordHash to verify against — there's no "current password" to
     * check, and no login path that would ever use a new one either, so
     * this is refused outright rather than silently no-oping.
     */
    public void changePassword(User user, ChangePasswordRequest request) {
        if (user.getPasswordHash() == null) {
            throw new PasswordChangeNotAllowedException(
                    "This account signed in with Google and has no password to change.");
        }
        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException();
        }
        validatePasswordStrength(request.newPassword());
        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        userRepository.save(user);
    }

    private void validatePasswordStrength(String password) {
        boolean hasLetter = password.chars().anyMatch(Character::isLetter);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        if (!hasLetter || !hasDigit) {
            throw new WeakPasswordException("Password must contain at least one letter and one digit");
        }
    }
}
