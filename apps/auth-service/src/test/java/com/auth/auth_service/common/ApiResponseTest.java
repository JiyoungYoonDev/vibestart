package com.auth.auth_service.common;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure unit tests for the ApiResponse record.
 * No Spring context is loaded — these tests are fast and dependency-free.
 */
class ApiResponseTest {

    // -------------------------------------------------------------------------
    // success(message, data) — generic overload
    // -------------------------------------------------------------------------

    @Test
    void success_withData_successIsTrue() {
        ApiResponse<String> response = ApiResponse.success("Operation succeeded", "payload");

        assertThat(response.success()).isTrue();
    }

    @Test
    void success_withData_messageIsMappedCorrectly() {
        String expectedMessage = "Operation succeeded";
        ApiResponse<String> response = ApiResponse.success(expectedMessage, "payload");

        assertThat(response.message()).isEqualTo(expectedMessage);
    }

    @Test
    void success_withStringData_dataIsMappedCorrectly() {
        ApiResponse<String> response = ApiResponse.success("OK", "some-payload");

        assertThat(response.data()).isEqualTo("some-payload");
    }

    @Test
    void success_withIntegerData_dataIsMappedCorrectly() {
        ApiResponse<Integer> response = ApiResponse.success("Count retrieved", 42);

        assertThat(response.data()).isEqualTo(42);
    }

    @Test
    void success_withMapData_dataContainsExpectedEntries() {
        Map<String, Object> payload = Map.of("id", 1, "name", "Alice");
        ApiResponse<Map<String, Object>> response = ApiResponse.success("User found", payload);

        assertThat(response.data())
                .containsEntry("id", 1)
                .containsEntry("name", "Alice");
    }

    @Test
    void success_withListData_dataHasExpectedSize() {
        List<String> items = List.of("a", "b", "c");
        ApiResponse<List<String>> response = ApiResponse.success("Items listed", items);

        assertThat(response.data()).hasSize(3).containsExactly("a", "b", "c");
    }

    // -------------------------------------------------------------------------
    // success(message) — no-data overload
    // -------------------------------------------------------------------------

    @Test
    void success_withoutData_successIsTrue() {
        ApiResponse<Void> response = ApiResponse.success("Done");

        assertThat(response.success()).isTrue();
    }

    @Test
    void success_withoutData_messageIsMappedCorrectly() {
        ApiResponse<Void> response = ApiResponse.success("Done");

        assertThat(response.message()).isEqualTo("Done");
    }

    @Test
    void success_withoutData_dataIsNull() {
        ApiResponse<Void> response = ApiResponse.success("Done");

        assertThat(response.data()).isNull();
    }

    // -------------------------------------------------------------------------
    // error(message, data) — generic overload
    // -------------------------------------------------------------------------

    @Test
    void error_withData_successIsFalse() {
        ApiResponse<String> response = ApiResponse.error("Something went wrong", "error-detail");

        assertThat(response.success()).isFalse();
    }

    @Test
    void error_withData_messageIsMappedCorrectly() {
        String expectedMessage = "Something went wrong";
        ApiResponse<String> response = ApiResponse.error(expectedMessage, "detail");

        assertThat(response.message()).isEqualTo(expectedMessage);
    }

    @Test
    void error_withStringData_dataIsMappedCorrectly() {
        ApiResponse<String> response = ApiResponse.error("Validation failed", "field: email");

        assertThat(response.data()).isEqualTo("field: email");
    }

    @Test
    void error_withMapData_dataContainsExpectedEntries() {
        Map<String, String> fieldErrors = Map.of(
                "email", "must be a valid email",
                "password", "must be at least 8 characters");

        ApiResponse<Map<String, String>> response = ApiResponse.error("Validation failed", fieldErrors);

        assertThat(response.success()).isFalse();
        assertThat(response.data())
                .containsEntry("email", "must be a valid email")
                .containsEntry("password", "must be at least 8 characters");
    }

    // -------------------------------------------------------------------------
    // error(message) — no-data overload
    // -------------------------------------------------------------------------

    @Test
    void error_withoutData_successIsFalse() {
        ApiResponse<Void> response = ApiResponse.error("Something went wrong");

        assertThat(response.success()).isFalse();
    }

    @Test
    void error_withoutData_messageIsMappedCorrectly() {
        ApiResponse<Void> response = ApiResponse.error("Something went wrong");

        assertThat(response.message()).isEqualTo("Something went wrong");
    }

    @Test
    void error_withoutData_dataIsNull() {
        ApiResponse<Void> response = ApiResponse.error("Something went wrong");

        assertThat(response.data()).isNull();
    }

    // -------------------------------------------------------------------------
    // Contrast: success vs error flags are mutually exclusive for same message
    // -------------------------------------------------------------------------

    @Test
    void successAndError_withSameMessage_haveOppositeSuccessFlags() {
        String message = "auth result";
        ApiResponse<Void> ok = ApiResponse.success(message);
        ApiResponse<Void> fail = ApiResponse.error(message);

        assertThat(ok.success()).isTrue();
        assertThat(fail.success()).isFalse();
    }

    // -------------------------------------------------------------------------
    // Record canonical constructor
    // -------------------------------------------------------------------------

    @Test
    void recordConstructor_storesAllFieldsAsSupplied() {
        ApiResponse<Integer> response = new ApiResponse<>(true, "custom", 99);

        assertThat(response.success()).isTrue();
        assertThat(response.message()).isEqualTo("custom");
        assertThat(response.data()).isEqualTo(99);
    }

    // -------------------------------------------------------------------------
    // Null-safe: passing null data explicitly via generic overload
    // -------------------------------------------------------------------------

    @Test
    void success_withExplicitNullData_dataIsNull() {
        ApiResponse<String> response = ApiResponse.success("OK", null);

        assertThat(response.success()).isTrue();
        assertThat(response.data()).isNull();
    }

    @Test
    void error_withExplicitNullData_dataIsNull() {
        ApiResponse<String> response = ApiResponse.error("Error", null);

        assertThat(response.success()).isFalse();
        assertThat(response.data()).isNull();
    }
}
