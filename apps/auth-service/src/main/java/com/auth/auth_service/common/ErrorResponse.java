package com.auth.auth_service.common;

import java.time.LocalDateTime;

/*
{
  "success":false,
  "code":"NOT_FOUND",
  "message":"Resource not found",
  "path":"/api/something",
  "timestamp":"2026-07-02T..."
    "details": {
    "email":"Email must be valid",
    "password":"Password must be at least 8 characters"
  }
}
*/
public record ErrorResponse<T> (
    boolean success,
    ErrorCode code,
    String message,
    String path,
    String timestamp,
    T details
) {
    public static ErrorResponse<Void> of(ErrorCode code, String message, String path) {
        return new ErrorResponse<>(false, code, message, path, LocalDateTime.now().toString(), null);
    }

    public static <T> ErrorResponse<T> of(ErrorCode code, String message, String path, T details) {
        return new ErrorResponse<>(false, code, message, path, LocalDateTime.now().toString(), details);
    }
}
