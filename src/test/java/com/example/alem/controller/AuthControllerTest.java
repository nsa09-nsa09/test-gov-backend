package com.example.alem.controller;

import com.example.alem.dto.VerifyTokenResponse;
import com.example.alem.service.JwksService;
import com.example.alem.service.KeycloakService;
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

    @BeforeEach
    void setUp() {
        AuthController controller = new AuthController(keycloakService, jwksService);
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
}
