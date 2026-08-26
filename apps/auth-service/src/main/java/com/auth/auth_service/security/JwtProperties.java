package com.auth.auth_service.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;

@Validated
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
    @NotBlank String secret,
    @Positive long expirationMs
) {
}
