package com.example.alem.controller;

import com.example.alem.dto.*;
import com.example.alem.service.JwksService;
import com.example.alem.service.KeycloakService;
import com.example.alem.service.KeycloakTotpApiService;
import com.example.alem.service.KeycloakTotpSetupService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.HttpCookie;
import java.net.URI;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final KeycloakService keycloakService;
    private final JwksService jwksService;
    private final KeycloakTotpSetupService keycloakTotpSetupService;
    private final KeycloakTotpApiService keycloakTotpApiService;

    @Autowired
    public AuthController(KeycloakService keycloakService,
                          JwksService jwksService,
                          @Autowired(required = false) KeycloakTotpSetupService keycloakTotpSetupService,
                          KeycloakTotpApiService keycloakTotpApiService) {
        this.keycloakService = keycloakService;
        this.jwksService = jwksService;
        this.keycloakTotpSetupService = keycloakTotpSetupService;
        this.keycloakTotpApiService = keycloakTotpApiService;
    }

    @Tag(name = "2. JWKS / Tokens")
    @Operation(summary = "Публичные ключи (JWKS)", description = """
            Публичные RSA-ключи Keycloak realm GovApps (проксируются и кэшируются alem).
            Используются second-backend для проверки id_token в legacy `POST /api/auth/exchange`.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "JWK Set",
                    content = @Content(schema = @Schema(implementation = Object.class), examples = @ExampleObject("""
                            {"keys": [{"kid": "Xx9kQ...", "kty": "RSA", "alg": "RS256", "use": "sig", "n": "...", "e": "AQAB"}]}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "Keycloak недоступен и кэша нет",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    @GetMapping(value = {"/jwks", "/.well-known/jwks.json"})
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok(jwksService.getPublicJwks());
    }

    @Tag(name = "2. JWKS / Tokens")
    @Operation(summary = "Проверить id_token", description = """
            Проверяет подпись RS256 id_token по JWKS, срок действия и возвращает claims.
            Невалидный токен возвращает `valid=false` со статусом 200.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Результат проверки",
                    content = @Content(schema = @Schema(implementation = VerifyTokenResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Пустой id_token",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    @PostMapping("/verify-id-token")
    public ResponseEntity<VerifyTokenResponse> verifyIdToken(@Valid @RequestBody VerifyTokenRequest request) {
        VerifyTokenResponse result = jwksService.verifyIdToken(request.idToken());
        return ResponseEntity.ok(result);
    }

    @Tag(name = "3. 2FA / TOTP")
    @Operation(summary = "Статус 2FA пользователя", description = """
            Через Keycloak Admin API проверяет, существует ли пользователь, есть ли у него OTP credential и required actions.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Статус 2FA (exists=false, если пользователь не найден)",
                    content = @Content(schema = @Schema(implementation = Check2faResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "500", description = "Ошибка Keycloak Admin API",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    @GetMapping("/check-2fa")
    public ResponseEntity<Check2faResponse> check2FA(@RequestParam(name = "username", required = false) String username) {
        Check2faResponse response = keycloakService.check2FA(username);
        return ResponseEntity.ok(response);
    }

    // --- Keycloak TOTP REST API Provider Endpoints (Native SPI) ---

    @Tag(name = "3. 2FA / TOTP")
    @Operation(summary = "Начать настройку TOTP", description = """
            Через Keycloak TOTP REST API Provider генерирует секрет и QR-код. `setup_id` из ответа передайте в `/2fa/totp/confirm`.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Секрет и QR-код",
                    content = @Content(schema = @Schema(implementation = TotpSetupResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Не удалось начать настройку",
                    content = @Content(schema = @Schema(implementation = TotpSetupResponse.class)))
    })
    @PostMapping("/2fa/totp/setup")
    public ResponseEntity<TotpSetupResponse> setupTotpNative(@Valid @RequestBody TotpSetupRequest request) {
        TotpSetupResponse response = keycloakTotpApiService.initiateSetup(request.username(), request.password());
        if (response.success()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @Tag(name = "3. 2FA / TOTP")
    @Operation(summary = "Подтвердить настройку TOTP", description = """
            Подтверждает настройку кодом из приложения-аутентификатора и сохраняет OTP credential в Keycloak.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "TOTP настроен",
                    content = @Content(schema = @Schema(implementation = TotpConfirmResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Неверный код или истекла сессия настройки",
                    content = @Content(schema = @Schema(implementation = TotpConfirmResponse.class)))
    })
    @PostMapping("/2fa/totp/confirm")
    public ResponseEntity<TotpConfirmResponse> confirmTotpNative(@Valid @RequestBody TotpConfirmRequest request) {
        TotpConfirmResponse response = keycloakTotpApiService.confirmSetup(
                request.setupId(),
                request.username(),
                request.code(),
                request.deviceName()
        );
        if (response.success()) {
            return ResponseEntity.ok(response);
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }
    }

    @Tag(name = "3. 2FA / TOTP")
    @Operation(summary = "Проверить TOTP-код", description = """
            Проверяет 6-значный код для пользователя и устройства.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Код верный",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": true, "message": "Код подтвержден успешно"}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Неверный код",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Неверный код TOTP"}""")))
    })
    @PostMapping("/2fa/totp/verify")
    public ResponseEntity<ApiResponse> verifyTotpNative(@Valid @RequestBody TotpVerifyRequest request) {
        boolean valid = keycloakTotpApiService.verifyCode(request.username(), request.code(), request.deviceName());
        if (valid) {
            return ResponseEntity.ok(ApiResponse.ok("Код подтвержден успешно"));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse(false, "Неверный код TOTP", null));
        }
    }

    @Tag(name = "3. 2FA / TOTP")
    @Operation(summary = "Список OTP-устройств", description = """
            OTP credentials пользователя в Keycloak.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Список устройств",
                    content = @Content(schema = @Schema(implementation = TotpDevicesResponse.class)))
    })
    @GetMapping("/2fa/totp/devices")
    public ResponseEntity<TotpDevicesResponse> getDevicesNative(@RequestParam("username") String username) {
        TotpDevicesResponse response = keycloakTotpApiService.getDevices(username);
        return ResponseEntity.ok(response);
    }

    @Tag(name = "3. 2FA / TOTP")
    @Operation(summary = "Удалить OTP-устройство", description = """
            Удаляет OTP credential пользователя по имени устройства.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Удалено",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": true, "message": "Устройство успешно удалено"}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Не удалось удалить",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Не удалось удалить устройство"}""")))
    })
    @DeleteMapping("/2fa/totp/devices")
    public ResponseEntity<ApiResponse> removeDeviceNative(
            @RequestParam("username") String username,
            @RequestParam(value = "device_name", defaultValue = "Google Authenticator") String deviceName) {
        boolean removed = keycloakTotpApiService.removeDevice(username, deviceName);
        if (removed) {
            return ResponseEntity.ok(ApiResponse.ok("Устройство успешно удалено"));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ApiResponse(false, "Не удалось удалить устройство", null));
        }
    }

    // --- Legacy Bridge & Fallback Endpoint ---
    @Tag(name = "4. Legacy")
    @Operation(summary = "[Legacy] Ссылка на настройку TOTP", description = """
            Сначала пробует TOTP REST API Provider, при неудаче — bridge-сессию Keycloak (ставит cookies Keycloak).
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Данные для настройки",
                    content = @Content(schema = @Schema(implementation = TotpSetupResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "503", description = "Bridge-сервис недоступен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    @PostMapping("/setup-totp-link")
    public ResponseEntity<TotpSetupResponse> setupTotpLink(@Valid @RequestBody SetupTotpLinkRequest request) {
        // Пробуем прямой вызов Keycloak TOTP API Provider
        try {
            TotpSetupResponse nativeResp = keycloakTotpApiService.initiateSetup(request.username(), request.password());
            if (nativeResp != null && nativeResp.success()) {
                return ResponseEntity.ok(nativeResp);
            }
        } catch (Exception e) {
            // fallback к bridge если провайдер вернул исключение
        }

        if (keycloakTotpSetupService == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }

        TotpSetupResponse response = keycloakTotpSetupService.initiateTotpSetup(request.username(), request.password());

        HttpHeaders headers = new HttpHeaders();
        if (response.bridgeUrl() != null && response.bridgeUrl().contains("ticket=")) {
            KeycloakTotpSetupService.BridgeSession session = keycloakTotpSetupService.getSessionByTicket(
                    response.bridgeUrl().substring(response.bridgeUrl().indexOf("ticket=") + 7)
            );

            if (session != null) {
                for (HttpCookie c : session.cookies()) {
                    ResponseCookie responseCookie = ResponseCookie.from(c.getName(), c.getValue())
                            .path("/")
                            .domain("localhost")
                            .sameSite("Lax")
                            .httpOnly(false)
                            .build();
                    headers.add(HttpHeaders.SET_COOKIE, responseCookie.toString());
                }
            }
        }

        return new ResponseEntity<>(response, headers, HttpStatus.OK);
    }

    @Tag(name = "4. Legacy")
    @Operation(summary = "[Legacy] Редирект на страницу настройки TOTP", description = """
            По `ticket` из `/setup-totp-link` ставит cookies сессии Keycloak и делает 302 на страницу настройки OTP.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "302", description = "Редирект в Keycloak",
                    content = @Content(schema = @Schema(implementation = Void.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Неизвестный ticket",
                    content = @Content(schema = @Schema(implementation = Void.class)))
    })
    @GetMapping("/setup-totp-bridge")
    public ResponseEntity<Void> setupTotpBridge(@RequestParam("ticket") String ticket) {
        if (keycloakTotpSetupService == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        KeycloakTotpSetupService.BridgeSession session = keycloakTotpSetupService.getSessionByTicket(ticket);
        if (session == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setLocation(URI.create(session.directQrUrl()));

        for (HttpCookie c : session.cookies()) {
            ResponseCookie responseCookie = ResponseCookie.from(c.getName(), c.getValue())
                    .path("/")
                    .domain("localhost")
                    .sameSite("Lax")
                    .httpOnly(false)
                    .build();
            headers.add(HttpHeaders.SET_COOKIE, responseCookie.toString());
        }

        return new ResponseEntity<>(headers, HttpStatus.FOUND);
    }

    @Tag(name = "1. Auth")
    @Operation(summary = "Логин (получение access token)", description = """
            Password grant в Keycloak для клиента `test-app` (scope `openid profile email`).
            
            **Token Exchange:** полученный `access_token` (`azp=test-app`, `aud` содержит `second-backend`)
            передайте в second-backend: `POST http://localhost:8081/api/auth/token-exchange` с телом
            `{"subject_token": "<access_token>"}` — в ответ придёт токен с `azp=second-backend`.
            
            Если у пользователя включена 2FA, передайте `otp`.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Токены Keycloak",
                    content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Пустой username/password",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Validation failed", "data": {"username": "Username is required"}}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Неверные креды, код 2FA или требуется настройка 2FA",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Invalid user credentials"}""")))
    })
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        TokenResponse tokens = keycloakService.login(request);
        return ResponseEntity.ok(tokens);
    }

    @Tag(name = "1. Auth")
    @Operation(summary = "Регистрация пользователя", description = """
            Создаёт пользователя в realm GovApps через Keycloak Admin API и устанавливает пароль.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "201", description = "Пользователь создан",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Ошибка валидации",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "409", description = "Username или email уже заняты",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Пользователь с именем 'aitu3' уже зарегистрирован"}""")))
    })
    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody RegisterRequest request) {
        Map<String, Object> createdUser = keycloakService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Пользователь успешно зарегистрирован в Keycloak", createdUser));
    }

    @Tag(name = "1. Auth")
    @Operation(summary = "Обновить токены", description = """
            refresh_token grant в Keycloak для клиента `test-app`. Тело: `{"refreshToken": "..."}`.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Новые токены",
                    content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "401", description = "Refresh token истёк или недействителен",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": false, "message": "Срок действия refresh токена истек или он недействителен."}""")))
    })
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        TokenResponse tokens = keycloakService.refresh(request.refreshToken());
        return ResponseEntity.ok(tokens);
    }

    @Tag(name = "1. Auth")
    @Operation(summary = "Выход", description = """
            Завершает сессию Keycloak по refresh token.
            """)
    @ApiResponses({
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "200", description = "Сессия завершена",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class), examples = @ExampleObject("""
                            {"success": true, "message": "Успешный выход из системы"}"""))),
            @io.swagger.v3.oas.annotations.responses.ApiResponse(responseCode = "400", description = "Ошибка валидации",
                    content = @Content(schema = @Schema(implementation = ApiResponse.class)))
    })
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(@Valid @RequestBody RefreshRequest request) {
        keycloakService.logout(request.refreshToken());
        return ResponseEntity.ok(ApiResponse.ok("Успешный выход из системы"));
    }
}
