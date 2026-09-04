package com.auth.auth_service.auth;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.RequestBody;
import com.auth.auth_service.auth.dto.SignupRequest;
import com.auth.auth_service.auth.dto.SignupResponse;
import com.auth.auth_service.security.AuthUserDetails;
import com.auth.auth_service.user.User;
import com.auth.auth_service.auth.dto.ChangePasswordRequest;
import com.auth.auth_service.auth.dto.GoogleLoginRequest;
import com.auth.auth_service.auth.dto.LoginRequest;
import com.auth.auth_service.auth.dto.LoginResponse;
import com.auth.auth_service.auth.dto.MeResponse;
import com.auth.auth_service.auth.dto.UpdateUsernameRequest;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    
    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(@Valid @RequestBody SignupRequest request) {
        SignupResponse response = authService.signup(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/google")
    public ResponseEntity<LoginResponse> loginWithGoogle(@Valid @RequestBody GoogleLoginRequest request) {
        LoginResponse response = authService.loginWithGoogle(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authHeader) {
        authService.logout(authHeader.substring(7));
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/me")
    public ResponseEntity<MeResponse> getMe(@AuthenticationPrincipal AuthUserDetails userDetails) {
        User user = userDetails.getUser();
        MeResponse response = new MeResponse(
            user.getId(),
            user.getEmail(),
            user.getUsername(),
            user.getRole(),
            user.getStatus()
        );
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/me")
    public ResponseEntity<MeResponse> updateMe(
            @AuthenticationPrincipal AuthUserDetails userDetails,
            @Valid @RequestBody UpdateUsernameRequest request) {
        User user = authService.updateUsername(userDetails.getUser(), request.username());
        MeResponse response = new MeResponse(
            user.getId(),
            user.getEmail(),
            user.getUsername(),
            user.getRole(),
            user.getStatus()
        );
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(
            @AuthenticationPrincipal AuthUserDetails userDetails,
            @Valid @RequestBody ChangePasswordRequest request) {
        authService.changePassword(userDetails.getUser(), request);
        return ResponseEntity.noContent().build();
    }
}
