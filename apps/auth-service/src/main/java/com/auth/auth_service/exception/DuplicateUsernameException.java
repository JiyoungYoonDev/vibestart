package com.auth.auth_service.exception;

public class DuplicateUsernameException extends RuntimeException {
    
    private final String username;

    public DuplicateUsernameException(String username) {
        super("Username already taken");
        this.username = username;
    }
    
    public String getUsername() {
        return username;
    }
}
