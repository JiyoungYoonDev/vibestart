package com.auth.auth_service.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * clientId is intentionally NOT @NotBlank — an empty value just means
 * Google sign-in is unconfigured (GoogleTokenVerifier rejects attempts to
 * use it), rather than a startup-blocking config error for deployments
 * that only need email/password auth.
 */
@ConfigurationProperties(prefix = "google")
public record GoogleAuthProperties(
    String clientId
) {
}
