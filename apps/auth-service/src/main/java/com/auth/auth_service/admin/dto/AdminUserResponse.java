package com.auth.auth_service.admin.dto;

import java.time.Instant;
import java.util.UUID;

import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;

// Mirrors MeResponse's shape — never expose passwordHash/googleId.
public record AdminUserResponse(
        UUID id,
        String email,
        String username,
        UserRole role,
        UserStatus status,
        Instant createdAt
) {}
