package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(description = "Регистрация пользователя в realm GovApps")
public record RegisterRequest(
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Schema(example = "aitu3")
    String username,

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Schema(example = "aitu3@example.com")
    String email,

    @Schema(example = "Aitu")
    String firstName,
    @Schema(example = "User")
    String lastName,

    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "Password must be at least 6 characters")
    @Schema(description = "Минимум 6 символов", example = "P@ssw0rd")
    String password
) {}
