package com.auth.auth_service.auth.dto;

import java.util.UUID;
import com.auth.auth_service.user.UserStatus;

public record SignupResponse(
    UUID id,
    String email,
    String username,
    UserStatus status
) {
}
