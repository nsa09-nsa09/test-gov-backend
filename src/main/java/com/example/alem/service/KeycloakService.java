package com.example.alem.service;

import com.example.alem.dto.*;
import com.example.alem.exception.AuthException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class KeycloakService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakService.class);

    @Value("${keycloak.server-url:http://localhost:8180}")
    private String serverUrl;

    @Value("${keycloak.realm:GovApps}")
    private String realm;

    @Value("${keycloak.client-id:test-app}")
    private String clientId;

    @Value("${keycloak.admin.realm:master}")
    private String adminRealm;

    @Value("${keycloak.admin.client-id:admin-cli}")
    private String adminClientId;

    @Value("${keycloak.admin.username:admin}")
    private String adminUsername;

    @Value("${keycloak.admin.password:admin}")
    private String adminPassword;

    private final RestClient restClient;
    private final ObjectMapper objectMapper;

    private final AtomicReference<String> cachedAdminToken = new AtomicReference<>(null);
    private volatile long adminTokenExpiry = 0;

    public KeycloakService() {
        this.restClient = RestClient.builder().build();
        this.objectMapper = new ObjectMapper()
                .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    // --- Admin Token with Caching ---
    private synchronized String getAdminToken() {
        long now = System.currentTimeMillis();
        if (cachedAdminToken.get() != null && now < adminTokenExpiry) {
            return cachedAdminToken.get();
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", adminClientId);
        form.add("grant_type", "password");
        form.add("username", adminUsername);
        form.add("password", adminPassword);

        try {
            String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, adminRealm);
            String respBody = restClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);

            TokenResponse resp = objectMapper.readValue(respBody, TokenResponse.class);

            if (resp != null && resp.accessToken() != null) {
                cachedAdminToken.set(resp.accessToken());
                long expiresInSec = resp.expiresIn() != null ? resp.expiresIn() : 60;
                adminTokenExpiry = now + (expiresInSec - 10) * 1000;
                return resp.accessToken();
            }
            throw new AuthException("Не удалось получить административный токен Keycloak", HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (Exception ex) {
            log.error("Failed to obtain Keycloak admin token: {}", ex.getMessage(), ex);
            throw new AuthException("Ошибка подключения к Keycloak Admin API: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // --- Check 2FA Status ---
    public Check2faResponse check2FA(String username) {
        if (username == null || username.isBlank()) {
            return Check2faResponse.notFound(username);
        }

        String adminToken = getAdminToken();
        try {
            String searchUrl = String.format("%s/admin/realms/%s/users?username=%s&exact=true", serverUrl, realm, username.trim());
            String usersJson = restClient.get()
                    .uri(searchUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .body(String.class);

            JsonNode usersNode = objectMapper.readTree(usersJson);
            if (usersNode == null || !usersNode.isArray() || usersNode.isEmpty()) {
                return Check2faResponse.notFound(username);
            }

            JsonNode userNode = usersNode.get(0);
            String userId = userNode.path("id").asText();
            String foundUsername = userNode.path("username").asText(username);
            String email = userNode.path("email").asText("");
            String firstName = userNode.path("firstName").asText("");
            String lastName = userNode.path("lastName").asText("");
            String fullName = (firstName + " " + lastName).trim();
            if (fullName.isEmpty()) fullName = foundUsername;

            String credsUrl = String.format("%s/admin/realms/%s/users/%s/credentials", serverUrl, realm, userId);
            String credsJson = restClient.get()
                    .uri(credsUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .body(String.class);

            JsonNode credsNode = objectMapper.readTree(credsJson);
            boolean has2fa = false;
            if (credsNode != null && credsNode.isArray()) {
                for (JsonNode cred : credsNode) {
                    if ("otp".equalsIgnoreCase(cred.path("type").asText())) {
                        has2fa = true;
                        break;
                    }
                }
            }

            // Проверяем, требует ли Keycloak настройку 2FA (CONFIGURE_TOTP в requiredActions)
            boolean configureTotpRequired = false;
            List<String> requiredActions = new ArrayList<>();
            JsonNode actionsNode = userNode.path("requiredActions");
            if (actionsNode.isArray()) {
                for (JsonNode act : actionsNode) {
                    String action = act.asText();
                    requiredActions.add(action);
                    if ("CONFIGURE_TOTP".equalsIgnoreCase(action)) {
                        configureTotpRequired = true;
                    }
                }
            }

            boolean needs2faSetup = !has2fa && configureTotpRequired;
            String setupUrl = null;
            if (needs2faSetup) {
                setupUrl = String.format("%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=http://localhost:5173/setup-callback.html&response_type=code&scope=openid&kc_action=CONFIGURE_TOTP",
                        serverUrl, realm, clientId);
            }

            return new Check2faResponse(true, has2fa, needs2faSetup, foundUsername, fullName, email, setupUrl, requiredActions);
        } catch (Exception ex) {
            log.error("Error checking 2FA for user '{}': {}", username, ex.getMessage(), ex);
            return Check2faResponse.notFound(username);
        }
    }

    // --- Login (Password Grant + OTP) ---
    public TokenResponse login(LoginRequest req) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("grant_type", "password");
        form.add("username", req.username().trim());
        form.add("password", req.password());

        if (req.otp() != null && !req.otp().isBlank()) {
            String cleanOtp = req.otp().trim().replaceAll("\\D", "");
            form.add("totp", cleanOtp);
            form.add("otp", cleanOtp);
        }

        form.add("scope", "openid profile email");

        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);

        try {
            String respBody = restClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);

            return objectMapper.readValue(respBody, TokenResponse.class);
        } catch (HttpClientErrorException.BadRequest ex) {
            String errorBody = ex.getResponseBodyAsString();
            String msg = "Неверный логин, пароль или код 2FA.";
            try {
                JsonNode errNode = objectMapper.readTree(errorBody);
                if (errNode.has("error_description")) {
                    msg = errNode.get("error_description").asText();
                }
            } catch (Exception ignored) {}

            // Если Keycloak сообщает, что аккаунт не настроен
            if (msg.contains("Account is not fully set up") || msg.contains("not fully set up")) {
                try {
                    Check2faResponse status = check2FA(req.username());
                    if (status.needs2faSetup()) {
                        msg = "Для вашего аккаунта включена двухфакторная аутентификация. Нажмите 'Настроить 2FA' и отсканируйте QR-код в Google Authenticator.";
                    } else if (status.requiredActions() != null && status.requiredActions().contains("UPDATE_PASSWORD")) {
                        msg = "Для аккаунта требуется сменить временный пароль в Keycloak (отключите опцию 'Temporary' в Keycloak Admin Console).";
                    } else if (status.requiredActions() != null && !status.requiredActions().isEmpty()) {
                        msg = "Аккаунт требует выполнения действий в Keycloak: " + String.join(", ", status.requiredActions());
                    } else {
                        msg = "Аккаунт не полностью настроен в Keycloak.";
                    }
                } catch (Exception e) {
                    msg = "Аккаунт не полностью настроен в Keycloak.";
                }
            }

            throw new AuthException(msg, HttpStatus.UNAUTHORIZED);
        } catch (Exception ex) {
            throw new AuthException("Ошибка при обращении к серверу аутентификации: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    // --- Register User ---
    public Map<String, Object> register(RegisterRequest req) {
        String adminToken = getAdminToken();

        // 1. Проверяем уникальность логина
        String checkUserUrl = String.format("%s/admin/realms/%s/users?username=%s&exact=true", serverUrl, realm, req.username().trim());
        String existingUserJson = restClient.get()
                .uri(checkUserUrl)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .body(String.class);

        JsonNode existingUser = null;
        try {
            existingUser = objectMapper.readTree(existingUserJson);
        } catch (Exception ignored) {}

        if (existingUser != null && existingUser.isArray() && !existingUser.isEmpty()) {
            throw new AuthException("Пользователь с именем '" + req.username() + "' уже зарегистрирован", HttpStatus.CONFLICT);
        }

        // 2. Проверяем уникальность email
        String checkEmailUrl = String.format("%s/admin/realms/%s/users?email=%s&exact=true", serverUrl, realm, req.email().trim());
        String existingEmailJson = restClient.get()
                .uri(checkEmailUrl)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .retrieve()
                .body(String.class);

        JsonNode existingEmail = null;
        try {
            existingEmail = objectMapper.readTree(existingEmailJson);
        } catch (Exception ignored) {}

        if (existingEmail != null && existingEmail.isArray() && !existingEmail.isEmpty()) {
            throw new AuthException("Пользователь с email '" + req.email() + "' уже зарегистрирован", HttpStatus.CONFLICT);
        }

        // 3. Создаем пользователя
        Map<String, Object> userPayload = Map.of(
                "username", req.username().trim(),
                "email", req.email().trim(),
                "firstName", req.firstName() != null ? req.firstName().trim() : "",
                "lastName", req.lastName() != null ? req.lastName().trim() : "",
                "enabled", true,
                "emailVerified", true
        );

        String createUserUrl = String.format("%s/admin/realms/%s/users", serverUrl, realm);
        String userId;

        try {
            String payloadJson = objectMapper.writeValueAsString(userPayload);
            ResponseEntity<Void> createResp = restClient.post()
                    .uri(createUserUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(payloadJson)
                    .retrieve()
                    .toBodilessEntity();

            URI location = createResp.getHeaders().getLocation();
            if (location != null) {
                String path = location.getPath();
                userId = path.substring(path.lastIndexOf('/') + 1);
            } else {
                // Если Location заголовок отсутствует, находим ID по username
                String createdJson = restClient.get()
                        .uri(checkUserUrl)
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                        .retrieve()
                        .body(String.class);
                JsonNode created = objectMapper.readTree(createdJson);
                if (created != null && created.isArray() && !created.isEmpty()) {
                    userId = created.get(0).path("id").asText();
                } else {
                    throw new AuthException("Пользователь создан, но не удалось получить ID", HttpStatus.INTERNAL_SERVER_ERROR);
                }
            }
        } catch (HttpClientErrorException.Conflict ex) {
            throw new AuthException("Пользователь с такими данными уже существует", HttpStatus.CONFLICT);
        } catch (AuthException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new AuthException("Ошибка при создании пользователя в Keycloak: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        // 4. Устанавливаем пароль
        Map<String, Object> passwordPayload = Map.of(
                "type", "password",
                "value", req.password(),
                "temporary", false
        );

        String resetPasswordUrl = String.format("%s/admin/realms/%s/users/%s/reset-password", serverUrl, realm, userId);
        try {
            String passJson = objectMapper.writeValueAsString(passwordPayload);
            restClient.put()
                    .uri(resetPasswordUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(passJson)
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception ex) {
            throw new AuthException("Пользователь создан, но не удалось установить пароль: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return Map.of(
                "userId", userId,
                "username", req.username(),
                "email", req.email()
        );
    }

    // --- Refresh Token ---
    public TokenResponse refresh(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);
        form.add("scope", "openid profile email");

        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);

        try {
            String respBody = restClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);

            return objectMapper.readValue(respBody, TokenResponse.class);
        } catch (Exception ex) {
            throw new AuthException("Срок действия refresh токена истек или он недействителен.", HttpStatus.UNAUTHORIZED);
        }
    }

    // --- Logout ---
    public void logout(String refreshToken) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("refresh_token", refreshToken);

        String logoutUrl = String.format("%s/realms/%s/protocol/openid-connect/logout", serverUrl, realm);

        try {
            restClient.post()
                    .uri(logoutUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .toBodilessEntity();
        } catch (Exception ignored) {
            // Logout best-effort
        }
    }
}
