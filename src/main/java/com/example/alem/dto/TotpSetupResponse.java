package com.example.alem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "Данные для настройки TOTP")
public record TotpSetupResponse(
    @Schema(example = "true")
    boolean success,
    @JsonProperty("setup_id")
    @Schema(description = "ID сессии настройки для /2fa/totp/confirm", example = "7f3c...")
    String setupId,
    @JsonProperty("qr_code_base64")
    @Schema(description = "QR-код PNG в base64")
    String qrCodeBase64,
    @JsonProperty("totp_secret")
    @Schema(description = "Секрет TOTP для ручного ввода", example = "JBSWY3DPEHPK3PXP")
    String totpSecret,
    @JsonProperty("expires_in_seconds")
    @Schema(description = "Сколько живёт сессия настройки", example = "300")
    Long expiresInSeconds,
    @JsonProperty("direct_qr_url")
    String directQrUrl,
    @JsonProperty("bridge_url")
    String bridgeUrl,
    @Schema(example = "aitu3")
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
