package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Начало настройки TOTP")
public record TotpSetupRequest(
    @NotBlank(message = "Username is required")
    @Schema(example = "aitu3")
    String username,
    @Schema(description = "Пароль пользователя (опционально)", example = "P@ssw0rd")
    String password
) {}
