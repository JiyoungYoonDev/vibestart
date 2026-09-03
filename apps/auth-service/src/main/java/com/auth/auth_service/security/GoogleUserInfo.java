package com.auth.auth_service.security;

public record GoogleUserInfo(
    String googleId,
    String email,
    boolean emailVerified,
    String name
) {}
