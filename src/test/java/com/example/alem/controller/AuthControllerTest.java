package com.example.alem.controller;

import com.example.alem.dto.TotpConfirmResponse;
import com.example.alem.dto.TotpSetupResponse;
import com.example.alem.dto.VerifyTokenResponse;
import com.example.alem.service.JwksService;
import com.example.alem.service.KeycloakService;
import com.example.alem.service.KeycloakTotpApiService;
import com.example.alem.service.KeycloakTotpSetupService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private KeycloakService keycloakService;

    @Mock
    private JwksService jwksService;

    @Mock
    private KeycloakTotpSetupService keycloakTotpSetupService;

    @Mock
    private KeycloakTotpApiService keycloakTotpApiService;

    @BeforeEach
    void setUp() {
        AuthController controller = new AuthController(keycloakService, jwksService, keycloakTotpSetupService, keycloakTotpApiService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    @Test
    void getJwks_returnsJwksMap() throws Exception {
        Map<String, Object> jwks = Map.of("keys", List.of(Map.of("kid", "key-1", "kty", "RSA", "alg", "RS256")));
        when(jwksService.getPublicJwks()).thenReturn(jwks);

        mockMvc.perform(get("/api/auth/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value("key-1"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"));
    }

    @Test
    void verifyIdToken_withValidToken_returnsOk() throws Exception {
        VerifyTokenResponse response = VerifyTokenResponse.success(
                "RS256", "key-1", "http://issuer", "sub-1",
                Map.of("email", "user@test.kz"),
                "OK"
        );
        when(jwksService.verifyIdToken(anyString())).thenReturn(response);

        mockMvc.perform(post("/api/auth/verify-id-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.algorithm").value("RS256"))
                .andExpect(jsonPath("$.key_id").value("key-1"))
                .andExpect(jsonPath("$.subject").value("sub-1"))
                .andExpect(jsonPath("$.claims.email").value("user@test.kz"));
    }

    @Test
    void verifyIdToken_withInvalidBody_returnsBadRequest() throws Exception {
        mockMvc.perform(post("/api/auth/verify-id-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"id_token": ""}
                                """))
                .andExpect(status().isBadRequest());
    }

    @Test
    void check2FA_whenSetupRequired_returnsNeedsSetupTrueAndUrl() throws Exception {
        com.example.alem.dto.Check2faResponse checkResp = new com.example.alem.dto.Check2faResponse(
                true, false, true, "newuser", "New User", "new@test.kz", "http://kc/setup"
        );
        when(keycloakService.check2FA("newuser")).thenReturn(checkResp);

        mockMvc.perform(get("/api/auth/check-2fa?username=newuser"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exists").value(true))
                .andExpect(jsonPath("$.has2fa").value(false))
                .andExpect(jsonPath("$.needs_2fa_setup").value(true))
                .andExpect(jsonPath("$.setup_url").value("http://kc/setup"));
    }

    @Test
    void setupTotpLink_withValidCredentials_returnsDirectQrUrl() throws Exception {
        TotpSetupResponse resp = new TotpSetupResponse(
                true,
                "http://localhost:8180/realms/GovApps/login-actions/required-action?execution=CONFIGURE_TOTP&client_id=test-app",
                "http://localhost:8080/api/auth/setup-totp-bridge?ticket=test-ticket",
                "data:image/png;base64,iVBORw0KGgo...",
                "SECRET123",
                "aitu3",
                "OK"
        );
        when(keycloakTotpSetupService.initiateTotpSetup("aitu3", "password")).thenReturn(resp);

        mockMvc.perform(post("/api/auth/setup-totp-link")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "aitu3", "password": "password"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.direct_qr_url").value("http://localhost:8180/realms/GovApps/login-actions/required-action?execution=CONFIGURE_TOTP&client_id=test-app"))
                .andExpect(jsonPath("$.bridge_url").value("http://localhost:8080/api/auth/setup-totp-bridge?ticket=test-ticket"))
                .andExpect(jsonPath("$.qr_code_base64").value("data:image/png;base64,iVBORw0KGgo..."))
                .andExpect(jsonPath("$.totp_secret").value("SECRET123"));
    }

    @Test
    void setupTotp_returnsDirectQrBase64() throws Exception {
        TotpSetupResponse resp = new TotpSetupResponse(
                true,
                "setup-123",
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
                "JBSWY3DPEHPK3PXP",
                300L,
                null,
                null,
                "aitu3",
                "QR-код для настройки 2FA успешно сгенерирован"
        );
        when(keycloakTotpApiService.initiateSetup(anyString(), anyString())).thenReturn(resp);

        mockMvc.perform(post("/api/auth/2fa/totp/setup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "aitu3", "password": "password"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.setup_id").value("setup-123"))
                .andExpect(jsonPath("$.qr_code_base64").value("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."))
                .andExpect(jsonPath("$.totp_secret").value("JBSWY3DPEHPK3PXP"))
                .andExpect(jsonPath("$.expires_in_seconds").value(300));
    }

    @Test
    void confirmTotp_returnsSuccess() throws Exception {
        TotpConfirmResponse resp = new TotpConfirmResponse(
                true,
                "aitu3",
                "TOTP успешно активирован и сохранен в Keycloak"
        );
        when(keycloakTotpApiService.confirmSetup(any(), any(), any(), any())).thenReturn(resp);

        mockMvc.perform(post("/api/auth/2fa/totp/confirm")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"setup_id": "setup-123", "username": "aitu3", "code": "123456"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.code").value("aitu3"));
    }
}
