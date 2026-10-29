package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Общий формат ответа")
public record ApiResponse(
    @Schema(example = "true")
    boolean success,
    @Schema(description = "Сообщение или причина ошибки", example = "Успешный выход из системы")
    String message,
    @Schema(description = "Данные ответа (зависит от endpoint)")
    Object data
) {
    public static ApiResponse ok(String message, Object data) {
        return new ApiResponse(true, message, data);
    }

    public static ApiResponse ok(String message) {
        return new ApiResponse(true, message, null);
    }

    public static ApiResponse error(String message) {
        return new ApiResponse(false, message, null);
    }
}
