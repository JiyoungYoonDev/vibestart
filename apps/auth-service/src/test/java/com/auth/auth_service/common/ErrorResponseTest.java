package com.auth.auth_service.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Pure unit tests for the ErrorResponse record.
 * No Spring context is loaded — these tests are fast and dependency-free.
 */
class ErrorResponseTest {

    // -------------------------------------------------------------------------
    // of(code, message, path) — no-details overload
    // -------------------------------------------------------------------------

    @Test
    void of_withoutDetails_successIsFalse() {
        // Arrange / Act
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "Resource not found", "/api/something");

        // Assert
        assertThat(response.success()).isFalse();
    }

    @Test
    void of_withoutDetails_detailsIsNull() {
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "Resource not found", "/api/something");

        assertThat(response.details()).isNull();
    }

    @Test
    void of_withoutDetails_codeIsMappedCorrectly() {
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "Resource not found", "/api/something");

        assertThat(response.code()).isEqualTo(ErrorCode.NOT_FOUND);
    }

    @Test
    void of_withoutDetails_messageIsMappedCorrectly() {
        String expectedMessage = "Resource not found";
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, expectedMessage, "/api/something");

        assertThat(response.message()).isEqualTo(expectedMessage);
    }

    @Test
    void of_withoutDetails_pathIsMappedCorrectly() {
        String expectedPath = "/api/something";
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "Resource not found", expectedPath);

        assertThat(response.path()).isEqualTo(expectedPath);
    }

    @Test
    void of_withoutDetails_timestampIsNotNull() {
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "Resource not found", "/api/something");

        assertThat(response.timestamp()).isNotNull();
    }

    @Test
    void of_withoutDetails_timestampIsValidIso8601Instant() {
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "Resource not found", "/api/something");

        // Instant.parse throws DateTimeParseException if the format is invalid
        assertThatCode(() -> Instant.parse(response.timestamp()))
                .doesNotThrowAnyException();
    }

    @Test
    void of_withoutDetails_timestampIsRecentlyGenerated() {
        Instant before = Instant.now();
        ErrorResponse<Void> response = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "Resource not found", "/api/something");
        Instant after = Instant.now();

        Instant parsed = Instant.parse(response.timestamp());
        assertThat(parsed).isBetween(before, after);
    }

    // -------------------------------------------------------------------------
    // of(code, message, path, details) — with-details overload
    // -------------------------------------------------------------------------

    @Test
    void of_withStringDetails_successIsFalse() {
        ErrorResponse<String> response = ErrorResponse.of(
                ErrorCode.VALIDATION_ERROR, "Validation failed", "/api/users", "email is required");

        assertThat(response.success()).isFalse();
    }

    @Test
    void of_withStringDetails_detailsIsPopulatedCorrectly() {
        String expectedDetails = "email is required";
        ErrorResponse<String> response = ErrorResponse.of(
                ErrorCode.VALIDATION_ERROR, "Validation failed", "/api/users", expectedDetails);

        assertThat(response.details()).isEqualTo(expectedDetails);
    }

    @Test
    void of_withMapDetails_detailsContainsExpectedEntries() {
        // Simulates a field-error map returned on validation failures
        Map<String, String> fieldErrors = Map.of(
                "email", "Email must be valid",
                "password", "Password must be at least 8 characters");

        ErrorResponse<Map<String, String>> response = ErrorResponse.of(
                ErrorCode.VALIDATION_ERROR, "Validation failed", "/api/register", fieldErrors);

        assertThat(response.details())
                .containsEntry("email", "Email must be valid")
                .containsEntry("password", "Password must be at least 8 characters");
    }

    @Test
    void of_withIntegerDetails_detailsIsPopulatedCorrectly() {
        ErrorResponse<Integer> response = ErrorResponse.of(
                ErrorCode.BAD_REQUEST, "Bad request", "/api/items", 42);

        assertThat(response.details()).isEqualTo(42);
    }

    @Test
    void of_withDetails_timestampIsValidIso8601Instant() {
        ErrorResponse<String> response = ErrorResponse.of(
                ErrorCode.CONFLICT, "Conflict", "/api/register", "extra info");

        assertThatCode(() -> Instant.parse(response.timestamp()))
                .doesNotThrowAnyException();
    }

    @Test
    void of_withDetails_codeAndMessageAndPathAreMappedCorrectly() {
        ErrorResponse<String> response = ErrorResponse.of(
                ErrorCode.UNAUTHORIZED, "Unauthorized access", "/api/secure", "token missing");

        assertThat(response.code()).isEqualTo(ErrorCode.UNAUTHORIZED);
        assertThat(response.message()).isEqualTo("Unauthorized access");
        assertThat(response.path()).isEqualTo("/api/secure");
    }

    // -------------------------------------------------------------------------
    // Parameterized — every ErrorCode value must be accepted without error
    // -------------------------------------------------------------------------

    @ParameterizedTest(name = "of() accepts ErrorCode.{0}")
    @EnumSource(ErrorCode.class)
    void of_withoutDetails_acceptsAllErrorCodes(ErrorCode code) {
        ErrorResponse<Void> response = ErrorResponse.of(code, "some message", "/some/path");

        assertThat(response.code()).isEqualTo(code);
        assertThat(response.success()).isFalse();
    }

    @ParameterizedTest(name = "of(details) accepts ErrorCode.{0}")
    @EnumSource(ErrorCode.class)
    void of_withDetails_acceptsAllErrorCodes(ErrorCode code) {
        ErrorResponse<String> response = ErrorResponse.of(code, "some message", "/some/path", "detail");

        assertThat(response.code()).isEqualTo(code);
        assertThat(response.details()).isEqualTo("detail");
    }

    // -------------------------------------------------------------------------
    // Record canonical constructor — direct instantiation
    // -------------------------------------------------------------------------

    @Test
    void recordConstructor_storesAllFieldsAsSupplied() {
        String fixedTimestamp = "2026-01-01T00:00:00Z";
        ErrorResponse<String> response = new ErrorResponse<>(
                false, ErrorCode.FORBIDDEN, "Forbidden", "/admin", fixedTimestamp, "extra");

        assertThat(response.success()).isFalse();
        assertThat(response.code()).isEqualTo(ErrorCode.FORBIDDEN);
        assertThat(response.message()).isEqualTo("Forbidden");
        assertThat(response.path()).isEqualTo("/admin");
        assertThat(response.timestamp()).isEqualTo(fixedTimestamp);
        assertThat(response.details()).isEqualTo("extra");
    }

    // -------------------------------------------------------------------------
    // Two calls to of() produce independent timestamps (not a singleton)
    // -------------------------------------------------------------------------

    @Test
    void of_calledTwiceInSequence_producesIndependentObjects() throws InterruptedException {
        ErrorResponse<Void> first = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "msg", "/path");
        // Small pause to guarantee the clock can tick at least one nanosecond
        Thread.sleep(1);
        ErrorResponse<Void> second = ErrorResponse.of(
                ErrorCode.NOT_FOUND, "msg", "/path");

        // They must be distinct objects
        assertThat(first).isNotSameAs(second);
        // The second timestamp must be >= the first
        assertThat(Instant.parse(second.timestamp()))
                .isAfterOrEqualTo(Instant.parse(first.timestamp()));
    }
}
