package com.example.alem;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.web.client.RestClient;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OpenApiDocsTest {

    @Value("${local.server.port}")
    private int port;

    @Test
    @DisplayName("/v3/api-docs содержит endpoints alem, Swagger UI доступен")
    void apiDocsContainsEndpoints() throws Exception {
        RestClient client = RestClient.create("http://localhost:" + port);

        JsonNode docs = new ObjectMapper().readTree(client.get().uri("/v3/api-docs").retrieve().body(String.class));
        JsonNode paths = docs.path("paths");

        for (String path : new String[]{
                "/api/auth/login", "/api/auth/register", "/api/auth/refresh", "/api/auth/logout",
                "/api/auth/jwks", "/api/auth/verify-id-token", "/api/auth/check-2fa",
                "/api/auth/2fa/totp/setup", "/api/auth/2fa/totp/confirm", "/api/auth/2fa/totp/verify",
                "/api/auth/2fa/totp/devices", "/api/auth/setup-totp-link", "/api/auth/setup-totp-bridge"}) {
            assertTrue(paths.has(path), "Нет пути в OpenAPI: " + path);
        }
        assertTrue(paths.path("/api/auth/login").path("post").path("description").asText().contains("token-exchange"));

        String ui = client.get().uri("/swagger-ui/index.html").retrieve().body(String.class);
        assertTrue(ui.contains("swagger-ui"));
    }
}
