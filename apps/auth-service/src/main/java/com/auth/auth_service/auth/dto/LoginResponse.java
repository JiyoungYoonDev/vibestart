package com.auth.auth_service.auth.dto;

public record LoginResponse(
    String accessToken,
    String tokenType,
    long expiresIn
) {}