package com.auth.auth_service.auth;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.crypto.password.PasswordEncoder;
import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.WeakPasswordException;
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

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
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
}
