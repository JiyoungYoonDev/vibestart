package com.auth.auth_service.admin;

import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.auth.auth_service.admin.dto.AdminUserResponse;
import com.auth.auth_service.admin.dto.UpdateUserStatusRequest;
import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRepository;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

// Real JWT-based admin auth (unlike woojoo-shop's shared-secret admin
// pattern) — the caller must be signed in as an actual account with
// role=ADMIN. JwtAuthFilter/AuthUserDetails already attach a ROLE_ADMIN
// GrantedAuthority for such accounts, so @PreAuthorize just works once
// @EnableMethodSecurity is on (see SecurityConfig).
@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {

    private final UserRepository userRepository;

    @GetMapping("/users")
    @PreAuthorize("hasRole('ADMIN')")
    public List<AdminUserResponse> listUsers() {
        return userRepository.findAll().stream().map(this::toDto).toList();
    }

    @PatchMapping("/users/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public AdminUserResponse updateStatus(@PathVariable UUID id, @Valid @RequestBody UpdateUserStatusRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found: " + id));
        user.setStatus(request.status());
        return toDto(userRepository.save(user));
    }

    private AdminUserResponse toDto(User user) {
        return new AdminUserResponse(
                user.getId(), user.getEmail(), user.getUsername(),
                user.getRole(), user.getStatus(), user.getCreatedAt()
        );
    }
}
