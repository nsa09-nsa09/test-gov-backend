package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "id_token для проверки подписи по JWKS")
public record VerifyTokenRequest(
    @JsonProperty("id_token")
    @JsonAlias("idToken")
    @NotBlank(message = "id_token обязателен для проверки")
    @Schema(example = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ...")
    String idToken
) {}
