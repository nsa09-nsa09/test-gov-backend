package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Подтверждение настройки TOTP кодом из приложения")
public record TotpConfirmRequest(
    @JsonProperty("setup_id")
    @Schema(description = "ID сессии настройки из /2fa/totp/setup", example = "7f3c...")
    String setupId,
    @NotBlank(message = "Username is required")
    @Schema(example = "aitu3")
    String username,
    @NotBlank(message = "Confirmation code is required")
    @Schema(description = "6-значный код из Google Authenticator", example = "123456")
    String code,
    @JsonProperty("device_name")
    @Schema(description = "Название устройства", example = "Google Authenticator")
    String deviceName
) {}
