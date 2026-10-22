package com.example.alem.dto;

import jakarta.validation.constraints.NotBlank;

public record TotpSetupRequest(
    @NotBlank(message = "Username is required")
    String username,
    String password
) {}
