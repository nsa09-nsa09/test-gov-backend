package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public record Check2faResponse(
    boolean exists,
    boolean has2fa,
    @JsonProperty("needs_2fa_setup")
    boolean needs2faSetup,
    String username,
    String name,
    String email,
    @JsonProperty("setup_url")
    String setupUrl,
    @JsonProperty("required_actions")
    List<String> requiredActions
) {
    public Check2faResponse(boolean exists, boolean has2fa, boolean needs2faSetup, String username, String name, String email, String setupUrl) {
        this(exists, has2fa, needs2faSetup, username, name, email, setupUrl, List.of());
    }

    public static Check2faResponse notFound(String username) {
        return new Check2faResponse(false, false, false, username, null, null, null, List.of());
    }
}
