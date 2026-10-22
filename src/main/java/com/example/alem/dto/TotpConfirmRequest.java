package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record TotpConfirmRequest(
    @JsonProperty("setup_id")
    String setupId,
    @NotBlank(message = "Username is required")
    String username,
    @NotBlank(message = "Confirmation code is required")
    String code,
    @JsonProperty("device_name")
    String deviceName
) {}
