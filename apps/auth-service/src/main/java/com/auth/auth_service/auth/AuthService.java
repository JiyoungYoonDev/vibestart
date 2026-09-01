package com.auth.auth_service.auth;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.WeakPasswordException;
import com.auth.auth_service.security.JwtProperties;
import com.auth.auth_service.security.JwtService;
import com.auth.auth_service.exception.InvalidCredentialsException;
import com.auth.auth_service.auth.dto.LoginRequest;
import com.auth.auth_service.auth.dto.LoginResponse;
import com.auth.auth_service.auth.dto.SignupRequest;
import com.auth.auth_service.auth.dto.SignupResponse;
import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRepository;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;

@Service
@Transactional
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final JwtProperties jwtProperties;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, JwtProperties jwtProperties) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
    }

    public SignupResponse signup(SignupRequest request) {
        if (userRepository.findByEmail(request.email()).isPresent()) {
            throw new DuplicateEmailException(request.email());
        }

        if (userRepository.findByUsername(request.username()).isPresent()) {
            throw new DuplicateUsernameException(request.username());
        }

        // password check
        String password = request.password();
        boolean hasLetter =
        password.chars().anyMatch(Character::isLetter);
        boolean hasDigit  =
        password.chars().anyMatch(Character::isDigit);
        if (!hasLetter || !hasDigit) {
            throw new WeakPasswordException("Password must contain at   least one letter and one digit");
        }

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

    public void logout(User user) {
        
        
    }
}
