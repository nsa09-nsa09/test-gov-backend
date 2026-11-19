package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Результат подтверждения TOTP")
public record TotpConfirmResponse(
    @Schema(example = "true")
    boolean success,
    @Schema(description = "Код результата", example = "OK")
    String code,
    @Schema(example = "TOTP успешно настроен")
    String message
) {}
