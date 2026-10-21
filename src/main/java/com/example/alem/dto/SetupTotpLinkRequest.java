package com.example.alem.dto;

import jakarta.validation.constraints.NotBlank;

public record SetupTotpLinkRequest(
    @NotBlank(message = "Username is required")
    String username,

    @NotBlank(message = "Password is required")
    String password
) {}
