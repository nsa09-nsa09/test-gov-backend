package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

@Schema(description = "Статус 2FA пользователя в Keycloak")
public record Check2faResponse(
    @Schema(description = "Пользователь найден", example = "true")
    boolean exists,
    @Schema(description = "У пользователя есть OTP credential", example = "false")
    boolean has2fa,
    @JsonProperty("needs_2fa_setup")
    @Schema(description = "Требуется required action CONFIGURE_TOTP", example = "true")
    boolean needs2faSetup,
    @Schema(example = "aitu3")
    String username,
    @Schema(example = "Aitu User")
    String name,
    @Schema(example = "aitu3@example.com")
    String email,
    @JsonProperty("setup_url")
    @Schema(description = "Ссылка на настройку 2FA в Keycloak")
    String setupUrl,
    @JsonProperty("required_actions")
    @Schema(description = "Required actions пользователя", example = "[\"CONFIGURE_TOTP\"]")
    List<String> requiredActions
) {
    public Check2faResponse(boolean exists, boolean has2fa, boolean needs2faSetup, String username, String name, String email, String setupUrl) {
        this(exists, has2fa, needs2faSetup, username, name, email, setupUrl, List.of());
    }

    public static Check2faResponse notFound(String username) {
        return new Check2faResponse(false, false, false, username, null, null, null, List.of());
    }
}
