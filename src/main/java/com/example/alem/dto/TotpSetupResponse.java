package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record TotpSetupResponse(
    boolean success,
    @JsonProperty("setup_id")
    String setupId,
    @JsonProperty("qr_code_base64")
    String qrCodeBase64,
    @JsonProperty("totp_secret")
    String totpSecret,
    @JsonProperty("expires_in_seconds")
    Long expiresInSeconds,
    @JsonProperty("direct_qr_url")
    String directQrUrl,
    @JsonProperty("bridge_url")
    String bridgeUrl,
    String username,
    String message
) {
    public TotpSetupResponse(
            boolean success,
            String directQrUrl,
            String bridgeUrl,
            String qrCodeBase64,
            String totpSecret,
            String username,
            String message
    ) {
        this(success, null, qrCodeBase64, totpSecret, null, directQrUrl, bridgeUrl, username, message);
    }
}
