package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Refresh token Keycloak (клиент test-app)")
public record RefreshRequest(
    @NotBlank(message = "Refresh token is required")
    @Schema(description = "Refresh token из ответа /login", example = "eyJhbGciOiJIUzUxMiIs...")
    String refreshToken
) {}
