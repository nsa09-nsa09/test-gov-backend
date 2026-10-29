package com.example.alem.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    public static final String BEARER_SCHEME = "bearerAuth";

    @Bean
    public OpenAPI alemOpenApi(@Value("${server.port:8080}") int port) {
        String description = """
                Основной backend GovApps (BFF над Keycloak, клиент `test-app`): логин, регистрация,
                обновление токенов, JWKS и 2FA (TOTP).

                ### Token Exchange со second-backend
                1. `POST /api/auth/login` → `access_token` (A): `azp=test-app`, `aud` содержит `second-backend`.
                2. A передаётся в second-backend: `POST http://localhost:8081/api/auth/token-exchange`.
                3. second-backend через Keycloak (RFC 8693) получает свой токен (B) с `azp=second-backend`.

                Swagger second-backend: http://localhost:8081/swagger-ui.html
                """;

        return new OpenAPI()
                .info(new Info()
                        .title("Alem (Main Backend) API")
                        .version("1.0.0")
                        .description(description))
                .servers(List.of(new Server().url("http://localhost:" + port).description("Local")))
                .components(new Components().addSecuritySchemes(BEARER_SCHEME, new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")));
    }
}
