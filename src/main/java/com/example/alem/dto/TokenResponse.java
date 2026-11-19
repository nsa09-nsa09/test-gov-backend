package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@Schema(description = "Токены Keycloak, выданные клиенту test-app")
public record TokenResponse(
    @JsonProperty("access_token")
    @Schema(description = "Access token (RS256, azp=test-app, aud содержит second-backend). Используйте как subject_token в second POST /api/auth/token-exchange", example = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ...")
    String accessToken,

    @JsonProperty("refresh_token")
    @Schema(description = "Refresh token", example = "eyJhbGciOiJIUzUxMiIs...")
    String refreshToken,

    @JsonProperty("id_token")
    @Schema(description = "OIDC id_token", example = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ...")
    String idToken,

    @JsonProperty("token_type")
    @Schema(example = "Bearer")
    String tokenType,

    @JsonProperty("expires_in")
    @Schema(description = "Время жизни access token, сек", example = "300")
    Long expiresIn,

    @JsonProperty("refresh_expires_in")
    @Schema(description = "Время жизни refresh token, сек", example = "1800")
    Long refreshExpiresIn,

    @Schema(example = "openid profile email")
    String scope
) {}

