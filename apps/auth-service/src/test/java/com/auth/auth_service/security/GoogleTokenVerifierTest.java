package com.auth.auth_service.security;

import com.auth.auth_service.exception.InvalidGoogleTokenException;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class GoogleTokenVerifierTest {

    private static final String CLIENT_ID = "test-client-id.apps.googleusercontent.com";

    private GoogleTokenVerifier verifierWithMockServer(MockRestServiceServer[] serverOut) {
        RestClient.Builder builder = RestClient.builder();
        serverOut[0] = MockRestServiceServer.bindTo(builder).build();
        return new GoogleTokenVerifier(new GoogleAuthProperties(CLIENT_ID), builder);
    }

    private String tokenInfoJson(String sub, String email, String emailVerified, String name, String aud) {
        return """
                {"sub": "%s", "email": "%s", "email_verified": "%s", "name": "%s", "aud": "%s"}
                """.formatted(sub, email, emailVerified, name, aud);
    }

    @Test
    void verify_validToken_returnsGoogleUserInfo() {
        MockRestServiceServer[] serverHolder = new MockRestServiceServer[1];
        GoogleTokenVerifier verifier = verifierWithMockServer(serverHolder);
        serverHolder[0].expect(requestTo(org.hamcrest.Matchers.containsString("oauth2.googleapis.com/tokeninfo")))
                .andRespond(withSuccess(
                        tokenInfoJson("g-sub-1", "Person@Example.com", "true", "Some Person", CLIENT_ID),
                        MediaType.APPLICATION_JSON));

        GoogleUserInfo info = verifier.verify("some-id-token");

        assertThat(info.googleId()).isEqualTo("g-sub-1");
        assertThat(info.email()).isEqualTo("person@example.com");
        assertThat(info.emailVerified()).isTrue();
        assertThat(info.name()).isEqualTo("Some Person");
    }

    @Test
    void verify_audDoesNotMatchConfiguredClientId_throwsInvalidGoogleTokenException() {
        MockRestServiceServer[] serverHolder = new MockRestServiceServer[1];
        GoogleTokenVerifier verifier = verifierWithMockServer(serverHolder);
        serverHolder[0].expect(requestTo(org.hamcrest.Matchers.containsString("oauth2.googleapis.com/tokeninfo")))
                .andRespond(withSuccess(
                        tokenInfoJson("g-sub-1", "person@example.com", "true", "Some Person", "someone-elses-client-id"),
                        MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> verifier.verify("some-id-token"))
                .isInstanceOf(InvalidGoogleTokenException.class);
    }

    @Test
    void verify_emailNotVerified_throwsInvalidGoogleTokenException() {
        MockRestServiceServer[] serverHolder = new MockRestServiceServer[1];
        GoogleTokenVerifier verifier = verifierWithMockServer(serverHolder);
        serverHolder[0].expect(requestTo(org.hamcrest.Matchers.containsString("oauth2.googleapis.com/tokeninfo")))
                .andRespond(withSuccess(
                        tokenInfoJson("g-sub-1", "person@example.com", "false", "Some Person", CLIENT_ID),
                        MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> verifier.verify("some-id-token"))
                .isInstanceOf(InvalidGoogleTokenException.class);
    }

    @Test
    void verify_googleRejectsToken_throwsInvalidGoogleTokenException() {
        MockRestServiceServer[] serverHolder = new MockRestServiceServer[1];
        GoogleTokenVerifier verifier = verifierWithMockServer(serverHolder);
        serverHolder[0].expect(requestTo(org.hamcrest.Matchers.containsString("oauth2.googleapis.com/tokeninfo")))
                .andRespond(withStatus(org.springframework.http.HttpStatus.BAD_REQUEST)
                        .body("{\"error_description\": \"Invalid Value\"}")
                        .contentType(MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> verifier.verify("expired-token"))
                .isInstanceOf(InvalidGoogleTokenException.class);
    }

    @Test
    void verify_clientIdNotConfigured_throwsInvalidGoogleTokenExceptionWithoutCallingGoogle() {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        GoogleTokenVerifier verifier = new GoogleTokenVerifier(new GoogleAuthProperties(""), builder);

        assertThatThrownBy(() -> verifier.verify("some-id-token"))
                .isInstanceOf(InvalidGoogleTokenException.class);

        server.verify();
    }
}
