package com.auth.auth_service.auth.dto;
import java.util.UUID;

import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;


public record MeResponse(
    UUID id,
    String email,
    String username,
    UserRole role,
    UserStatus status
) {
    
}
