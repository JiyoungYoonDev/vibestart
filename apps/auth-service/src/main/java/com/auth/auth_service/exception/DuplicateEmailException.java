package com.auth.auth_service.exception;

public class DuplicateEmailException extends RuntimeException {

    private final String email;

    public DuplicateEmailException(String email) {
        super("Email already exists.");
        this.email = email;
    }

    public String getEmail() {
        return email;
    }
}
