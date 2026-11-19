package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "OTP-устройства пользователя")
public record TotpDevicesResponse(
    @Schema(example = "true")
    boolean success,
    @Schema(example = "aitu3")
    String username,
    @Schema(example = "[\"Google Authenticator\"]")
    List<String> devices,
    String message
) {}
