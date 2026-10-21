package com.example.alem.controller;

import com.example.alem.dto.*;
import com.example.alem.service.JwksService;
import com.example.alem.service.KeycloakService;
import com.example.alem.service.KeycloakTotpSetupService;
import jakarta.validation.Valid;
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

    public AuthController(KeycloakService keycloakService, JwksService jwksService) {
        this(keycloakService, jwksService, null);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public AuthController(KeycloakService keycloakService,
                          JwksService jwksService,
                          KeycloakTotpSetupService keycloakTotpSetupService) {
        this.keycloakService = keycloakService;
        this.jwksService = jwksService;
        this.keycloakTotpSetupService = keycloakTotpSetupService;
    }

    @GetMapping(value = {"/jwks", "/.well-known/jwks.json"})
    public ResponseEntity<Map<String, Object>> getJwks() {
        return ResponseEntity.ok(jwksService.getPublicJwks());
    }

    @PostMapping("/verify-id-token")
    public ResponseEntity<VerifyTokenResponse> verifyIdToken(@Valid @RequestBody VerifyTokenRequest request) {
        VerifyTokenResponse result = jwksService.verifyIdToken(request.idToken());
        return ResponseEntity.ok(result);
    }

    @GetMapping("/check-2fa")
    public ResponseEntity<Check2faResponse> check2FA(@RequestParam(name = "username", required = false) String username) {
        Check2faResponse response = keycloakService.check2FA(username);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/setup-totp-link")
    public ResponseEntity<TotpSetupResponse> setupTotpLink(@Valid @RequestBody SetupTotpLinkRequest request) {
        TotpSetupResponse response = keycloakTotpSetupService.initiateTotpSetup(request.username(), request.password());

        // Выставляем куки для localhost, чтобы при открытии прямой ссылки браузер уже имел сессионный контекст
        HttpHeaders headers = new HttpHeaders();
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

        return new ResponseEntity<>(response, headers, HttpStatus.OK);
    }

    @GetMapping("/setup-totp-bridge")
    public ResponseEntity<Void> setupTotpBridge(@RequestParam("ticket") String ticket) {
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

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody LoginRequest request) {
        TokenResponse tokens = keycloakService.login(request);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse> register(@Valid @RequestBody RegisterRequest request) {
        Map<String, Object> createdUser = keycloakService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.ok("Пользователь успешно зарегистрирован в Keycloak", createdUser));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        TokenResponse tokens = keycloakService.refresh(request.refreshToken());
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(@Valid @RequestBody RefreshRequest request) {
        keycloakService.logout(request.refreshToken());
        return ResponseEntity.ok(ApiResponse.ok("Успешный выход из системы"));
    }
}
