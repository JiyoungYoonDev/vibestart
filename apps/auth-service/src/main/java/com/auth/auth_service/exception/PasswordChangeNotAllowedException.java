package com.auth.auth_service.exception;

public class PasswordChangeNotAllowedException extends RuntimeException {
    public PasswordChangeNotAllowedException(String message) {
        super(message);
    }
}
