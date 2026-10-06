package com.example.alem.controller;

import com.example.alem.dto.*;
import com.example.alem.service.JwksService;
import com.example.alem.service.KeycloakService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final KeycloakService keycloakService;
    private final JwksService jwksService;

    public AuthController(KeycloakService keycloakService, JwksService jwksService) {
        this.keycloakService = keycloakService;
        this.jwksService = jwksService;
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
