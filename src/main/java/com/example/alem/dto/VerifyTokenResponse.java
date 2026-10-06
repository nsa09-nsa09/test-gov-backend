package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record VerifyTokenResponse(
    boolean valid,
    String algorithm,
    @JsonProperty("key_id")
    String keyId,
    String issuer,
    String subject,
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
