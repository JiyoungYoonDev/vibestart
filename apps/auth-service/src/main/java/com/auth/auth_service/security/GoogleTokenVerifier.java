package com.auth.auth_service.security;

import com.auth.auth_service.exception.InvalidGoogleTokenException;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Verifies a Google ID token by delegating signature/expiry checks to
 * Google's own tokeninfo endpoint, rather than pulling in the full Google
 * API client just to validate a JWT against Google's rotating JWKS. Fine
 * for this app's traffic volume — Google's own docs list this endpoint as
 * suitable for server-side verification, just not recommended at very high
 * QPS because of its per-IP rate limit.
 */
@Service
public class GoogleTokenVerifier {
    private static final String TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo";

    private final RestClient restClient;
    private final GoogleAuthProperties properties;

    public GoogleTokenVerifier(GoogleAuthProperties properties, RestClient.Builder restClientBuilder) {
        this.properties = properties;
        this.restClient = restClientBuilder.build();
    }

    public GoogleUserInfo verify(String idToken) {
        if (properties.clientId() == null || properties.clientId().isBlank()) {
            throw new InvalidGoogleTokenException("Google sign-in is not configured on this server");
        }

        TokenInfoResponse response;
        try {
            response = restClient.get()
                    .uri(TOKENINFO_URL + "?id_token={idToken}", idToken)
                    .retrieve()
                    .body(TokenInfoResponse.class);
        } catch (RestClientException e) {
            throw new InvalidGoogleTokenException("Google rejected the sign-in token");
        }

        if (response == null || response.sub() == null || response.email() == null) {
            throw new InvalidGoogleTokenException("Google token response was incomplete");
        }
        if (!properties.clientId().equals(response.aud())) {
            throw new InvalidGoogleTokenException("Google token was not issued for this app");
        }
        if (!"true".equals(response.emailVerified())) {
            throw new InvalidGoogleTokenException("Google account email is not verified");
        }

        return new GoogleUserInfo(response.sub(), response.email().toLowerCase(), true, response.name());
    }

    private record TokenInfoResponse(
            String sub,
            String email,
            @JsonProperty("email_verified") String emailVerified,
            String name,
            String aud) {
    }
}
