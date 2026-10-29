package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Логин пользователя через Keycloak (password grant, клиент test-app)")
public record LoginRequest(
    @NotBlank(message = "Username is required")
    @Schema(example = "aitu3")
    String username,

    @NotBlank(message = "Password is required")
    @Schema(example = "P@ssw0rd")
    String password,

    @Schema(description = "6-значный TOTP-код, если у пользователя включена 2FA", example = "123456")
    String otp
) {}
