package com.auth.auth_service.common;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import com.auth.auth_service.exception.DuplicateEmailException;
import com.auth.auth_service.exception.DuplicateUsernameException;
import com.auth.auth_service.exception.InvalidCredentialsException;
import com.auth.auth_service.exception.WeakPasswordException;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

        /**
         * Handles Spring MVC standard exceptions (404, 405, 400 etc.) that are
         * already mapped by ResponseEntityExceptionHandler. We override to wrap
         * them in our standard ErrorResponse shape.
         */
        private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

        @Override
        protected ResponseEntity<Object> handleExceptionInternal(
                        Exception ex,
                        Object body,
                        HttpHeaders headers,
                        HttpStatusCode statusCode,
                        WebRequest request) {
                ErrorCode code = resolveErrorCode(statusCode);
                ErrorResponse<Void> errorResponse = ErrorResponse.of(
                                code,
                                ex.getMessage() != null ? ex.getMessage() : statusCode.toString(),
                                request.getDescription(false).replace("uri=", ""));

                return ResponseEntity
                                .status(statusCode)
                                .headers(headers)
                                .body(errorResponse);
        }

        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<ErrorResponse<Void>> handleRuntimeException(
                        RuntimeException ex,
                        HttpServletRequest request) {
                logger.error("RuntimeException occurred: {}", request.getRequestURI(), ex);

                ErrorResponse<Void> response = ErrorResponse.of(
                                ErrorCode.INTERNAL_SERVER_ERROR,
                                "Unexpected server error",
                                request.getRequestURI());

                return ResponseEntity
                                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(response);
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<ErrorResponse<Void>> handleException(
                        Exception ex,
                        HttpServletRequest request) {

                logger.error("Unexpected exception occurred at URI: {}", request.getRequestURI(), ex);
                ErrorResponse<Void> response = ErrorResponse.of(
                                ErrorCode.INTERNAL_SERVER_ERROR,
                                "Unexpected server error",
                                request.getRequestURI());

                return ResponseEntity
                                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(response);
        }

        @Override
        protected ResponseEntity<Object> handleMethodArgumentNotValid(
                        MethodArgumentNotValidException ex,
                        HttpHeaders headers,
                        HttpStatusCode status,
                        WebRequest request) {
                Map<String, String> details = new LinkedHashMap<>();
                ex.getBindingResult().getFieldErrors()
                                .forEach(error -> details.put(error.getField(), error.getDefaultMessage()));

                ErrorResponse<Map<String, String>> body = ErrorResponse.of(
                                ErrorCode.VALIDATION_ERROR,
                                "Validation failed",
                                request.getDescription(false).replace("uri=", ""),
                                details);
                return ResponseEntity
                                .status(HttpStatus.BAD_REQUEST)
                                .body(body);
        }

        @ExceptionHandler(WeakPasswordException.class)
        public ResponseEntity<ErrorResponse<Map<String, String>>> handleWeakPassword(
                        WeakPasswordException ex,
                        HttpServletRequest request) {

                Map<String, String> details = Map.of("password", ex.getMessage());

                ErrorResponse<Map<String, String>> body = ErrorResponse.of(
                                ErrorCode.VALIDATION_ERROR,
                                "Validation failed",
                                request.getRequestURI(),
                                details);

                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
        }

        @ExceptionHandler(DuplicateEmailException.class)
        public ResponseEntity<ErrorResponse<Void>> handleDuplicateEmail(
                        DuplicateEmailException ex,
                        HttpServletRequest request) {

                logger.warn("Signup attempted with already-registered email: {}",
                                ex.getEmail());

                ErrorResponse<Void> body = ErrorResponse.of(
                                ErrorCode.EMAIL_ALREADY_EXISTS,
                                "An account with this email already exists",
                                request.getRequestURI());

                return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
        }
        @ExceptionHandler(DuplicateUsernameException.class)
        public ResponseEntity<ErrorResponse<Void>> handleDuplicateUsername(
                DuplicateUsernameException ex,
                HttpServletRequest request) {

        logger.warn("Signup attempted with already-taken username: {}",
        ex.getUsername());

        ErrorResponse<Void> body = ErrorResponse.of(
                ErrorCode.USERNAME_ALREADY_EXISTS,
                "This username is already taken",
                request.getRequestURI()
        );

        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
        }

        @ExceptionHandler(InvalidCredentialsException.class)
        public ResponseEntity<ErrorResponse<Void>> handleInvalidCredentials(
                InvalidCredentialsException ex,
                HttpServletRequest request) {

        ErrorResponse<Void> body = ErrorResponse.of(
                ErrorCode.INVALID_CREDENTIALS,
                "Invalid credentials",
                request.getRequestURI());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
        }
        private ErrorCode resolveErrorCode(HttpStatusCode statusCode) {
                int value = statusCode.value();
                return switch (value) {
                        case 400 -> ErrorCode.BAD_REQUEST;
                        case 401 -> ErrorCode.UNAUTHORIZED;
                        case 403 -> ErrorCode.FORBIDDEN;
                        case 404 -> ErrorCode.NOT_FOUND;
                        case 409 -> ErrorCode.CONFLICT;
                        default -> ErrorCode.INTERNAL_SERVER_ERROR;
                };
        }
}
