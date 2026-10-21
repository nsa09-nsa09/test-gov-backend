package com.example.alem.exception;

import org.springframework.http.HttpStatus;

public class AuthException extends RuntimeException {
    private final HttpStatus status;
    private final Object data;

    public AuthException(String message, HttpStatus status, Object data) {
        super(message);
        this.status = status;
        this.data = data;
    }

    public AuthException(String message, HttpStatus status) {
        this(message, status, null);
    }

    public AuthException(String message) {
        this(message, HttpStatus.BAD_REQUEST, null);
    }

    public HttpStatus getStatus() {
        return status;
    }

    public Object getData() {
        return data;
    }
}
