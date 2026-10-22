package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record TotpVerifyRequest(
    @NotBlank(message = "Username is required")
    String username,
    @NotBlank(message = "TOTP code is required")
    String code,
    @JsonProperty("device_name")
    String deviceName
) {}
