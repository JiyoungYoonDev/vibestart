# API Response Guide

## Overview

`auth-service` uses two common response formats.

- Success responses use `ApiResponse<T>`
- Error responses use `ErrorResponse<T>`

Related source files:

- `src/main/java/com/auth/auth_service/common/ApiResponse.java`
- `src/main/java/com/auth/auth_service/common/ErrorResponse.java`
- `src/main/java/com/auth/auth_service/common/ErrorCode.java`
- `src/main/java/com/auth/auth_service/common/GlobalExceptionHandler.java`

## Success Response

`ApiResponse<T>` structure:

```json
{
  "success": true,
  "message": "string",
  "data": {}
}
```

Fields:

- `success`: always `true` for successful responses
- `message`: human-readable success message
- `data`: payload data; can be `null`

Java definition:

```java
public record ApiResponse<T>(boolean success, String message, T data)
```

Factory methods:

```java
ApiResponse.success(String message, T data)
ApiResponse.success(String message)
ApiResponse.error(String message, T data)
ApiResponse.error(String message)
```

Note:

- `ApiResponse.error(...)` exists, but the current global exception flow returns `ErrorResponse`, not `ApiResponse`

### Success Response Example

Health check endpoint:

- `GET /api/v1/health`

Response:

```json
{
  "success": true,
  "message": "Auth Service is up and running!",
  "data": null
}
```

## Error Response

`ErrorResponse<T>` structure:

```json
{
  "success": false,
  "code": "INTERNAL_SERVER_ERROR",
  "message": "Unexpected server error",
  "path": "/api/v1/health/exception/runtime",
  "timestamp": "2026-07-02T17:30:00",
  "details": null
}
```

Fields:

- `success`: always `false` for error responses
- `code`: application error code from `ErrorCode`
- `message`: human-readable error message
- `path`: request URI where the error happened
- `timestamp`: error creation time
- `details`: optional extra data; can be `null`

Java definition:

```java
public record ErrorResponse<T>(
    boolean success,
    ErrorCode code,
    String message,
    String path,
    String timestamp,
    T details
)
```

Factory methods:

```java
ErrorResponse.of(ErrorCode code, String message, String path)
ErrorResponse.of(ErrorCode code, String message, String path, T details)
```

## Error Codes

Current `ErrorCode` values:

- `VALIDATION_ERROR`
- `BAD_REQUEST`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `NOT_FOUND`
- `CONFLICT`
- `INTERNAL_SERVER_ERROR`
- `EMAIL_ALREADY_EXISTS`
- `INVALID_CREDENTIALS`
- `TOKEN_EXPIRED`
- `INVALID_TOKEN`

## Global Exception Handling

`GlobalExceptionHandler` currently handles:

- `RuntimeException`
- `Exception`

Both handlers return:

- HTTP status: `500 Internal Server Error`
- body type: `ResponseEntity<ErrorResponse<Void>>`

Current error body pattern:

```json
{
  "success": false,
  "code": "INTERNAL_SERVER_ERROR",
  "message": "Unexpected server error",
  "path": "/requested/path",
  "timestamp": "2026-07-02T17:30:00",
  "details": null
}
```

## Current Health Endpoints

Defined in `HealthController`:

- `GET /api/v1/health`
- `GET /api/v1/health/readiness`
- `GET /api/v1/health/liveness`
- `GET /api/v1/health/exception/runtime`

### `GET /api/v1/health`

```json
{
  "success": true,
  "message": "Auth Service is up and running!",
  "data": null
}
```

### `GET /api/v1/health/readiness`

```json
{
  "success": true,
  "message": "Auth Service is ready to accept requests!",
  "data": null
}
```

### `GET /api/v1/health/liveness`

```json
{
  "success": true,
  "message": "Auth Service is alive!",
  "data": null
}
```

### `GET /api/v1/health/exception/runtime`

This endpoint intentionally throws a `RuntimeException` for exception handling tests.

Example response:

```json
{
  "success": false,
  "code": "INTERNAL_SERVER_ERROR",
  "message": "Unexpected server error",
  "path": "/api/v1/health/exception/runtime",
  "timestamp": "2026-07-02T17:30:00",
  "details": null
}
```

## Recommended Usage

- Use `ApiResponse<T>` for normal successful controller responses
- Use `ErrorResponse<T>` for exceptions and failure cases that need structured error metadata
- Put business-specific detail payloads in `details` when needed
- Keep `message` readable for clients, and keep `code` stable for frontend or API consumers
