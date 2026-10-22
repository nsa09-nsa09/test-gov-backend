package com.example.alem.service;

import com.example.alem.dto.*;
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
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class KeycloakTotpApiService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakTotpApiService.class);
    private static final long DEFAULT_TTL_SECONDS = 300L; // 5 минут

    @Value("${keycloak.server-url:http://localhost:8180}")
    private String serverUrl;

    @Value("${keycloak.realm:GovApps}")
    private String realm;

    @Value("${keycloak.service-client.client-id:alem-backend}")
    private String serviceClientId;

    @Value("${keycloak.service-client.client-secret:alem-secret-key-12345}")
    private String serviceClientSecret;

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

    // Кеш токена Service Account
    private final AtomicReference<String> cachedServiceToken = new AtomicReference<>(null);
    private volatile long serviceTokenExpiry = 0;

    // Кеш токена Admin (master realm) для поиска пользователей
    private final AtomicReference<String> cachedAdminToken = new AtomicReference<>(null);
    private volatile long adminTokenExpiry = 0;

    // Временное хранилище незавершенных настроек TOTP
    private final Map<String, PendingTotpSetup> pendingSetups = new ConcurrentHashMap<>();

    public record PendingTotpSetup(
            String setupId,
            String userId,
            String username,
            String encodedSecret,
            Instant expiresAt
    ) {
        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    public KeycloakTotpApiService() {
        this.restClient = RestClient.builder().build();
        this.objectMapper = new ObjectMapper()
                .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    // --- 1. Service Account Token (GovApps Realm) ---
    private synchronized String getServiceAccountToken() {
        long now = System.currentTimeMillis();
        if (cachedServiceToken.get() != null && now < serviceTokenExpiry) {
            return cachedServiceToken.get();
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", serviceClientId);
        form.add("client_secret", serviceClientSecret);

        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, realm);
        try {
            String respBody = restClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);

            JsonNode root = objectMapper.readTree(respBody);
            String token = root.path("access_token").asText();
            long expiresIn = root.path("expires_in").asLong(60L);

            cachedServiceToken.set(token);
            serviceTokenExpiry = now + (expiresIn - 15) * 1000;
            return token;
        } catch (Exception e) {
            log.error("Failed to obtain Service Account token for client {}: {}", serviceClientId, e.getMessage());
            throw new RuntimeException("Не удалось получить сервисный токен Keycloak: " + e.getMessage(), e);
        }
    }

    // --- 2. Master Admin Token (для поиска пользователя) ---
    private synchronized String getAdminToken() {
        long now = System.currentTimeMillis();
        if (cachedAdminToken.get() != null && now < adminTokenExpiry) {
            return cachedAdminToken.get();
        }

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", adminClientId);
        form.add("username", adminUsername);
        form.add("password", adminPassword);

        String tokenUrl = String.format("%s/realms/%s/protocol/openid-connect/token", serverUrl, adminRealm);
        try {
            String respBody = restClient.post()
                    .uri(tokenUrl)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);

            JsonNode root = objectMapper.readTree(respBody);
            String token = root.path("access_token").asText();
            long expiresIn = root.path("expires_in").asLong(60L);

            cachedAdminToken.set(token);
            adminTokenExpiry = now + (expiresIn - 15) * 1000;
            return token;
        } catch (Exception e) {
            log.error("Failed to obtain master admin token: {}", e.getMessage());
            throw new RuntimeException("Не удалось получить административный токен Keycloak", e);
        }
    }

    // --- 3. Поиск UUID пользователя по username ---
    public String resolveUserId(String username) {
        if (username == null || username.isBlank()) {
            throw new IllegalArgumentException("Имя пользователя не указано");
        }

        // Если уже передан UUID (36 символов с дефисами)
        if (username.matches("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")) {
            return username;
        }

        String adminToken = getAdminToken();
        String searchUrl = String.format("%s/admin/realms/%s/users?username=%s&exact=true", serverUrl, realm, username.trim());

        try {
            String respBody = restClient.get()
                    .uri(searchUrl)
                    .header("Authorization", "Bearer " + adminToken)
                    .retrieve()
                    .body(String.class);

            JsonNode usersNode = objectMapper.readTree(respBody);
            if (usersNode.isArray() && !usersNode.isEmpty()) {
                return usersNode.get(0).path("id").asText();
            }
            throw new NoSuchElementException("Пользователь " + username + " не найден в realm " + realm);
        } catch (NoSuchElementException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error resolving user id for {}: {}", username, e.getMessage());
            throw new RuntimeException("Ошибка поиска пользователя в Keycloak: " + e.getMessage(), e);
        }
    }

    // --- 4. Генерация TOTP и QR-кода ---
    public TotpSetupResponse initiateSetup(String username, String password) {
        purgeExpiredSetups();

        String userId = resolveUserId(username);
        String serviceToken = getServiceAccountToken();

        String generateUrl = String.format("%s/realms/%s/totp-api/%s/generate", serverUrl, realm, userId);

        try {
            String respBody = restClient.get()
                    .uri(generateUrl)
                    .header("Authorization", "Bearer " + serviceToken)
                    .retrieve()
                    .body(String.class);

            JsonNode root = objectMapper.readTree(respBody);
            String encodedSecret = root.path("encodedSecret").asText();
            String rawQrCode = root.path("qrCode").asText();

            if (encodedSecret == null || encodedSecret.isBlank()) {
                throw new IllegalStateException("Keycloak totp-api не вернул encodedSecret");
            }

            String qrCodeBase64 = rawQrCode.startsWith("data:")
                    ? rawQrCode
                    : "data:image/png;base64," + rawQrCode;

            String setupId = UUID.randomUUID().toString();
            Instant expiresAt = Instant.now().plusSeconds(DEFAULT_TTL_SECONDS);

            PendingTotpSetup pending = new PendingTotpSetup(setupId, userId, username, encodedSecret, expiresAt);
            pendingSetups.put(setupId, pending);

            log.info("TOTP QR-код успешно сгенерирован через Keycloak SPI: user={}, setupId={}", username, setupId);

            return new TotpSetupResponse(
                    true,
                    setupId,
                    qrCodeBase64,
                    encodedSecret,
                    DEFAULT_TTL_SECONDS,
                    null,
                    null,
                    username,
                    "QR-код успешно сгенерирован через Keycloak TOTP API"
            );
        } catch (Exception e) {
            log.error("Ошибка при генерации TOTP для user {}: {}", username, e.getMessage(), e);
            return new TotpSetupResponse(
                    false,
                    null,
                    null,
                    null,
                    0L,
                    null,
                    null,
                    username,
                    "Не удалось сгенерировать QR-код: " + e.getMessage()
            );
        }
    }

    // --- 5. Подтверждение и активация TOTP ---
    public TotpConfirmResponse confirmSetup(String setupId, String username, String code, String deviceName) {
        purgeExpiredSetups();

        if (code == null || code.isBlank()) {
            return new TotpConfirmResponse(false, "EMPTY_CODE", "Код подтверждения не может быть пустым");
        }

        String cleanCode = code.replaceAll("\\D", "");
        if (cleanCode.length() != 6) {
            return new TotpConfirmResponse(false, "INVALID_CODE_FORMAT", "Код должен состоять ровно из 6 цифр");
        }

        PendingTotpSetup pending = null;
        if (setupId != null && !setupId.isBlank()) {
            pending = pendingSetups.get(setupId.trim());
        }

        // Если setupId не передан или не найден, ищем по username
        if (pending == null && username != null && !username.isBlank()) {
            pending = pendingSetups.values().stream()
                    .filter(p -> p.username().equalsIgnoreCase(username.trim()) && !p.isExpired())
                    .max(Comparator.comparing(PendingTotpSetup::expiresAt))
                    .orElse(null);
        }

        if (pending == null || pending.isExpired()) {
            return new TotpConfirmResponse(false, "SETUP_EXPIRED", "Срок действия настройки истек. Запросите новый QR-код.");
        }

        String userId = pending.userId();
        String serviceToken = getServiceAccountToken();
        String registerUrl = String.format("%s/realms/%s/totp-api/%s/register", serverUrl, realm, userId);

        Map<String, Object> body = new HashMap<>();
        body.put("deviceName", deviceName != null && !deviceName.isBlank() ? deviceName.trim() : "Google Authenticator");
        body.put("encodedSecret", pending.encodedSecret());
        body.put("initialCode", cleanCode);
        body.put("overwrite", true);

        try {
            ResponseEntity<String> response = restClient.post()
                    .uri(registerUrl)
                    .header("Authorization", "Bearer " + serviceToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .toEntity(String.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                pendingSetups.remove(pending.setupId());
                removeConfigureTotpRequiredAction(userId);
                log.info("TOTP успешно подтвержден и сохранен в Keycloak для user {}", pending.username());
                return new TotpConfirmResponse(true, "SUCCESS", "2FA успешно настроена и активирована");
            } else {
                log.warn("Keycloak register вернул статус {}", response.getStatusCode());
                return new TotpConfirmResponse(false, "TOTP_REGISTRATION_FAILED", "Keycloak вернул код " + response.getStatusCode());
            }
        } catch (HttpClientErrorException.BadRequest e) {
            log.warn("Неверный код подтверждения TOTP для user {}: {}", pending.username(), e.getResponseBodyAsString());
            return new TotpConfirmResponse(false, "TOTP_INVALID_CODE", "Неверный код подтверждения. Проверьте время на устройстве и попробуйте снова.");
        } catch (Exception e) {
            log.error("Ошибка подтверждения TOTP для user {}: {}", pending.username(), e.getMessage());
            return new TotpConfirmResponse(false, "SERVER_ERROR", "Ошибка подтверждения 2FA: " + e.getMessage());
        }
    }

    // --- 6. Проверка разового TOTP кода ---
    public boolean verifyCode(String username, String code, String deviceName) {
        String cleanCode = code != null ? code.replaceAll("\\D", "") : "";
        if (cleanCode.length() != 6) {
            return false;
        }

        String userId = resolveUserId(username);
        String serviceToken = getServiceAccountToken();
        String verifyUrl = String.format("%s/realms/%s/totp-api/%s/verify", serverUrl, realm, userId);

        Map<String, String> body = new HashMap<>();
        body.put("deviceName", deviceName != null && !deviceName.isBlank() ? deviceName.trim() : "Google Authenticator");
        body.put("code", cleanCode);

        try {
            ResponseEntity<String> response = restClient.post()
                    .uri(verifyUrl)
                    .header("Authorization", "Bearer " + serviceToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .toEntity(String.class);

            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            log.warn("Проверка TOTP кода не прошла для user {}: {}", username, e.getMessage());
            return false;
        }
    }

    // --- 7. Получение списка устройств ---
    public TotpDevicesResponse getDevices(String username) {
        String userId = resolveUserId(username);
        String serviceToken = getServiceAccountToken();
        String devicesUrl = String.format("%s/realms/%s/totp-api/%s/get-totp-credentials", serverUrl, realm, userId);

        try {
            String respBody = restClient.get()
                    .uri(devicesUrl)
                    .header("Authorization", "Bearer " + serviceToken)
                    .retrieve()
                    .body(String.class);

            JsonNode root = objectMapper.readTree(respBody);
            List<String> devices = new ArrayList<>();
            JsonNode deviceNode = root.path("deviceName");
            if (deviceNode.isArray()) {
                for (JsonNode d : deviceNode) {
                    devices.add(d.asText());
                }
            }

            return new TotpDevicesResponse(true, username, devices, "Устройства получены");
        } catch (Exception e) {
            log.error("Ошибка при получении устройств TOTP для user {}: {}", username, e.getMessage());
            return new TotpDevicesResponse(false, username, List.of(), e.getMessage());
        }
    }

    // --- 8. Удаление TOTP устройства ---
    public boolean removeDevice(String username, String deviceName) {
        String userId = resolveUserId(username);
        String serviceToken = getServiceAccountToken();
        String removeUrl = String.format("%s/realms/%s/totp-api/%s/remove-totp", serverUrl, realm, userId);

        Map<String, String> body = new HashMap<>();
        body.put("deviceName", deviceName != null && !deviceName.isBlank() ? deviceName.trim() : "Google Authenticator");

        try {
            ResponseEntity<String> response = restClient.post()
                    .uri(removeUrl)
                    .header("Authorization", "Bearer " + serviceToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .retrieve()
                    .toEntity(String.class);

            return response.getStatusCode().is2xxSuccessful();
        } catch (Exception e) {
            log.error("Ошибка при удалении TOTP устройства {} для {}: {}", deviceName, username, e.getMessage());
            return false;
        }
    }

    private void removeConfigureTotpRequiredAction(String userId) {
        try {
            String adminToken = getAdminToken();
            String userUrl = String.format("%s/admin/realms/%s/users/%s", serverUrl, realm, userId);
            String userJson = restClient.get()
                    .uri(userUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .retrieve()
                    .body(String.class);

            JsonNode userNode = objectMapper.readTree(userJson);
            List<String> actions = new ArrayList<>();
            if (userNode.has("requiredActions") && userNode.get("requiredActions").isArray()) {
                for (JsonNode a : userNode.get("requiredActions")) {
                    if (!"CONFIGURE_TOTP".equalsIgnoreCase(a.asText())) {
                        actions.add(a.asText());
                    }
                }
            }

            Map<String, Object> update = new HashMap<>();
            update.put("requiredActions", actions);
            restClient.put()
                    .uri(userUrl)
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(update)
                    .retrieve()
                    .toBodilessEntity();
            log.info("Успешно очищено CONFIGURE_TOTP из requiredActions пользователя {}", userId);
        } catch (Exception e) {
            log.warn("Не удалось очистить CONFIGURE_TOTP для userId {}: {}", userId, e.getMessage());
        }
    }

    private void purgeExpiredSetups() {
        pendingSetups.entrySet().removeIf(entry -> entry.getValue().isExpired());
    }
}
