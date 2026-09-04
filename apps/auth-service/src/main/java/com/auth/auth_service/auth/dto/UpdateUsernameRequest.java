package com.auth.auth_service.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record UpdateUsernameRequest(
    @NotBlank(message = "Username is required")
    String username
) {
}
