package com.example.alem.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TotpSetupResponse(
    boolean success,
    @JsonProperty("direct_qr_url")
    String directQrUrl,
    @JsonProperty("bridge_url")
    String bridgeUrl,
    @JsonProperty("qr_code_base64")
    String qrCodeBase64,
    @JsonProperty("totp_secret")
    String totpSecret,
    String username,
    String message
) {}
