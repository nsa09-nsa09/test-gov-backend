package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Результат проверки id_token")
public record VerifyTokenResponse(
    @Schema(example = "true")
    boolean valid,
    @Schema(example = "RS256")
    String algorithm,
    @JsonProperty("key_id")
    @Schema(example = "Xx9kQ...")
    String keyId,
    @Schema(example = "http://localhost:8180/realms/GovApps")
    String issuer,
    @Schema(example = "b2f67ac1-...")
    String subject,
    @Schema(description = "Все claims токена")
    Map<String, Object> claims,
    String message
) {
    public static VerifyTokenResponse success(String alg, String kid, String iss, String sub, Map<String, Object> claims, String message) {
        return new VerifyTokenResponse(true, alg, kid, iss, sub, claims, message);
    }

    public static VerifyTokenResponse failure(String message) {
        return new VerifyTokenResponse(false, null, null, null, null, null, message);
    }

    public static VerifyTokenResponse failure(String alg, String kid, String message) {
        return new VerifyTokenResponse(false, alg, kid, null, null, null, message);
    }
}
