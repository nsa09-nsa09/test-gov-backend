package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

public record VerifyTokenRequest(
    @JsonProperty("id_token")
    @JsonAlias("idToken")
    @NotBlank(message = "id_token обязателен для проверки")
    String idToken
) {}
