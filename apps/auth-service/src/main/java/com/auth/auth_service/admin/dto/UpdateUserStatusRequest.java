package com.auth.auth_service.admin.dto;

import com.auth.auth_service.user.UserStatus;
import jakarta.validation.constraints.NotNull;

public record UpdateUserStatusRequest(@NotNull UserStatus status) {}
