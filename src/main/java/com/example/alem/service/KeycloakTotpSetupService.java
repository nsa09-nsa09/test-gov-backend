package com.example.alem.service;

import com.example.alem.dto.TotpSetupResponse;
import com.example.alem.exception.AuthException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class KeycloakTotpSetupService {

    private static final Logger log = LoggerFactory.getLogger(KeycloakTotpSetupService.class);

    private static final Pattern ACTION_PATTERN = Pattern.compile("action=\"([^\"]+login-actions/authenticate[^\"]*)\"");
    private static final Pattern QR_CODE_PATTERN = Pattern.compile("id=\"kc-totp-secret-qr-code\"\\s+src=\"([^\"]+)\"");
    private static final Pattern QR_FALLBACK_PATTERN = Pattern.compile("src=\"(data:image/png;base64,[^\"]+)\"");
    private static final Pattern SECRET_KEY_PATTERN = Pattern.compile("id=\"kc-totp-secret-key\">([^<]+)<");
    private static final Pattern SECRET_INPUT_PATTERN = Pattern.compile("id=\"totpSecret\"\\s+name=\"totpSecret\"\\s+value=\"([^\"]+)\"");
    private static final Pattern SUBMIT_ACTION_PATTERN = Pattern.compile("action=\"([^\"]+login-actions/required-action[^\"]*)\"");

    @Value("${keycloak.server-url:http://localhost:8180}")
    private String serverUrl;

    @Value("${keycloak.realm:GovApps}")
    private String realm;

    @Value("${keycloak.client-id:test-app}")
    private String clientId;

    public record BridgeSession(
            String ticketId,
            String username,
            String directQrUrl,
            List<HttpCookie> cookies,
            String actionUrl,
            String totpSecret,
            Instant expiresAt
    ) {
        public boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }

    private final Map<String, BridgeSession> ticketStore = new ConcurrentHashMap<>();

    public TotpSetupResponse initiateTotpSetup(String username, String password) {
        if (username == null || username.isBlank() || password == null || password.isBlank()) {
            throw new AuthException("Логин и пароль обязательны для инициализации настройки 2FA", HttpStatus.BAD_REQUEST);
        }

        CookieManager cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL) {
            @Override
            public void put(URI uri, Map<String, List<String>> responseHeaders) throws IOException {
                super.put(uri, responseHeaders);
                // Разрешаем отправку кук по обычному HTTP (localhost)
                for (HttpCookie c : getCookieStore().getCookies()) {
                    c.setSecure(false);
                }
            }
        };

        HttpClient httpClient = HttpClient.newBuilder()
                .cookieHandler(cookieManager)
                .followRedirects(HttpClient.Redirect.ALWAYS)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        try {
            // 1. Инициируем auth-запрос с kc_action=CONFIGURE_TOTP
            String authUrl = String.format(
                    "%s/realms/%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=http://localhost:5173/setup-callback.html&response_type=code&scope=openid&kc_action=CONFIGURE_TOTP",
                    serverUrl, realm, clientId
            );

            log.info("Запуск headless аутентификации Keycloak для '{}': {}", username, authUrl);

            HttpRequest authReq = HttpRequest.newBuilder()
                    .uri(URI.create(authUrl))
                    .GET()
                    .build();

            HttpResponse<String> authResp = httpClient.send(authReq, HttpResponse.BodyHandlers.ofString());

            if (authResp.statusCode() >= 400) {
                log.error("Keycloak вернул HTTP {} при инициировании auth", authResp.statusCode());
                throw new AuthException("Ошибка Keycloak при открытии страницы авторизации: " + authResp.statusCode(), HttpStatus.BAD_GATEWAY);
            }

            String authHtml = authResp.body();
            String loginActionUrl = extractLoginActionUrl(authHtml);
            if (loginActionUrl == null) {
                log.error("Не удалось найти login-actions/authenticate в HTML ответе Keycloak");
                throw new AuthException("Не удалось получить URL формы аутентификации Keycloak", HttpStatus.INTERNAL_SERVER_ERROR);
            }

            // 2. Отправляем учетные данные пользователя
            String formBody = String.format("username=%s&password=%s&credentialId=",
                    URLEncoder.encode(username.trim(), StandardCharsets.UTF_8),
                    URLEncoder.encode(password, StandardCharsets.UTF_8));

            HttpRequest loginReq = HttpRequest.newBuilder()
                    .uri(URI.create(loginActionUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(formBody))
                    .build();

            HttpResponse<String> loginResp = httpClient.send(loginReq, HttpResponse.BodyHandlers.ofString());
            String finalUrl = loginResp.uri().toString();
            String finalHtml = loginResp.body();

            log.info("Ответ формы аутентификации: HTTP {}, Final URL: {}", loginResp.statusCode(), finalUrl);

            // Проверяем, попали ли мы на экран CONFIGURE_TOTP
            boolean isTotpPage = finalUrl.contains("execution=CONFIGURE_TOTP") ||
                                 finalHtml.contains("kc-totp-secret-qr-code") ||
                                 finalHtml.contains("data:image/png;base64");

            if (!isTotpPage) {
                // Если мы остались на форме входа, проверяем текст ошибки
                if (finalHtml.contains("Invalid username or password") ||
                    finalHtml.contains("Неверное имя пользователя или пароль") ||
                    (finalHtml.contains("kc-feedback-text") && !finalHtml.contains("kc-totp"))) {
                    throw new AuthException("Неверный логин или пароль", HttpStatus.UNAUTHORIZED);
                }
                log.warn("Пользователь '{}' не попал на страницу CONFIGURE_TOTP (Final URL: {})", username, finalUrl);
                throw new AuthException("Для пользователя '" + username + "' настройка 2FA не требуется или аккаунт уже настроен", HttpStatus.BAD_REQUEST);
            }

            // 3. Извлекаем QR-код, секретный ключ и submit action
            String qrCodeBase64 = extractQrCode(finalHtml);
            String totpSecret = extractTotpSecret(finalHtml);
            String submitActionUrl = extractSubmitActionUrl(finalHtml);

            // 4. Сохраняем сессию моста (действует 10 минут)
            String ticketId = UUID.randomUUID().toString();
            List<HttpCookie> cookies = new ArrayList<>(cookieManager.getCookieStore().getCookies());

            BridgeSession session = new BridgeSession(
                    ticketId,
                    username,
                    finalUrl,
                    cookies,
                    submitActionUrl,
                    totpSecret,
                    Instant.now().plus(Duration.ofMinutes(10))
            );
            cleanExpiredTickets();
            ticketStore.put(ticketId, session);

            String bridgeUrl = "http://localhost:8080/api/auth/setup-totp-bridge?ticket=" + ticketId;

            return new TotpSetupResponse(
                    true,
                    finalUrl,
                    bridgeUrl,
                    qrCodeBase64,
                    totpSecret,
                    username,
                    "QR-код для настройки 2FA успешно сгенерирован в Keycloak"
            );

        } catch (AuthException ae) {
            throw ae;
        } catch (Exception ex) {
            log.error("Исключение при генерации QR-кода Keycloak: {}", ex.getMessage(), ex);
            throw new AuthException("Ошибка генерации ссылки на QR-код: " + ex.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public BridgeSession getSessionByTicket(String ticketId) {
        if (ticketId == null) return null;
        BridgeSession session = ticketStore.get(ticketId);
        if (session != null && session.isExpired()) {
            ticketStore.remove(ticketId);
            return null;
        }
        return session;
    }

    private void cleanExpiredTickets() {
        ticketStore.entrySet().removeIf(e -> e.getValue().isExpired());
    }

    private String extractLoginActionUrl(String html) {
        Matcher m = ACTION_PATTERN.matcher(html);
        if (m.find()) {
            return m.group(1).replace("&amp;", "&");
        }
        return null;
    }

    private String extractQrCode(String html) {
        Matcher m = QR_CODE_PATTERN.matcher(html);
        if (m.find()) {
            return m.group(1);
        }
        Matcher fallback = QR_FALLBACK_PATTERN.matcher(html);
        if (fallback.find()) {
            return fallback.group(1);
        }
        return null;
    }

    private String extractTotpSecret(String html) {
        Matcher m = SECRET_KEY_PATTERN.matcher(html);
        if (m.find()) {
            return m.group(1).trim();
        }
        Matcher inputMatcher = SECRET_INPUT_PATTERN.matcher(html);
        if (inputMatcher.find()) {
            return inputMatcher.group(1).trim();
        }
        return null;
    }

    private String extractSubmitActionUrl(String html) {
        Matcher m = SUBMIT_ACTION_PATTERN.matcher(html);
        if (m.find()) {
            return m.group(1).replace("&amp;", "&");
        }
        return null;
    }
}
