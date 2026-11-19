package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Запрос на получение ссылки/QR для настройки TOTP")
public record SetupTotpLinkRequest(
    @NotBlank(message = "Username is required")
    @Schema(example = "aitu3")
    String username,

    @NotBlank(message = "Password is required")
    @Schema(example = "P@ssw0rd")
    String password
) {}
