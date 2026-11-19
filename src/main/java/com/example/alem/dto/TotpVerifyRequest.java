package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Проверка TOTP-кода")
public record TotpVerifyRequest(
    @NotBlank(message = "Username is required")
    @Schema(example = "aitu3")
    String username,
    @NotBlank(message = "TOTP code is required")
    @Schema(example = "123456")
    String code,
    @JsonProperty("device_name")
    @Schema(example = "Google Authenticator")
    String deviceName
) {}
