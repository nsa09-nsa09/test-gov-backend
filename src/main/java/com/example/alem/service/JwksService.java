package com.example.alem.service;

import com.example.alem.dto.VerifyTokenResponse;
import com.example.alem.exception.AuthException;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.text.ParseException;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@Service
public class JwksService {

    private static final Logger log = LoggerFactory.getLogger(JwksService.class);

    @Value("${keycloak.server-url:http://localhost:8180}")
    private String serverUrl;

    @Value("${keycloak.realm:GovApps}")
    private String realm;

    private final RestClient restClient;
    private final AtomicReference<JWKSet> cachedJwkSet = new AtomicReference<>(null);
    private volatile long jwkSetExpiry = 0;

    public JwksService() {
        this.restClient = RestClient.builder().build();
    }

    /**
     * Возвращает публичный набор ключей JWKS в виде Map (формат RFC 7517).
     */
    public Map<String, Object> getPublicJwks() {
        return getJwkSet(false).toJSONObject();
    }

    /**
     * Получает JWKSet из кэша либо с сервера Keycloak.
     */
    public JWKSet getJwkSet(boolean forceRefresh) {
        long now = System.currentTimeMillis();
        if (!forceRefresh && cachedJwkSet.get() != null && now < jwkSetExpiry) {
            return cachedJwkSet.get();
        }
        return reloadJwkSet();
    }

    private synchronized JWKSet reloadJwkSet() {
        long now = System.currentTimeMillis();
        String jwksUrl = String.format("%s/realms/%s/protocol/openid-connect/certs", serverUrl, realm);
        try {
            log.info("Загрузка публичных ключей JWKS из {}", jwksUrl);
            String jwksJson = restClient.get()
                    .uri(jwksUrl)
                    .retrieve()
                    .body(String.class);

            JWKSet jwkSet = JWKSet.parse(jwksJson);
            JWKSet publicJwkSet = jwkSet.toPublicJWKSet();
            cachedJwkSet.set(publicJwkSet);
            jwkSetExpiry = now + 60 * 60 * 1000; // 1 час TTL
            return publicJwkSet;
        } catch (Exception ex) {
            log.error("Не удалось получить JWKS из {}: {}", jwksUrl, ex.getMessage(), ex);
            if (cachedJwkSet.get() != null) {
                log.warn("Используется устаревший кэш JWKS");
                return cachedJwkSet.get();
            }
            throw new AuthException("Не удалось получить публичные ключи JWKS от Keycloak: " + ex.getMessage(),
                    HttpStatus.SERVICE_UNAVAILABLE);
        }
    }

    /**
     * Валидация криптографической подписи и клеймов ID-токена через публичный JWKS.
     */
    public VerifyTokenResponse verifyIdToken(String idTokenString) {
        if (idTokenString == null || idTokenString.isBlank()) {
            return VerifyTokenResponse.failure("id_token не может быть пустым");
        }

        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(idTokenString.trim());
        } catch (ParseException e) {
            return VerifyTokenResponse.failure("Некорректный формат JWT токена: " + e.getMessage());
        }

        JWSHeader header = signedJWT.getHeader();
        String kid = header.getKeyID();
        String alg = header.getAlgorithm() != null ? header.getAlgorithm().getName() : "UNKNOWN";

        if (kid == null || kid.isBlank()) {
            return VerifyTokenResponse.failure(alg, null, "В заголовке токена отсутствует идентификатор ключа (kid)");
        }

        JWKSet jwkSet = getJwkSet(false);
        JWK jwk = jwkSet.getKeyByKeyId(kid);

        // Если ключ не найден, пробуем один раз форсированно обновить JWKS (на случай ротации ключей)
        if (jwk == null) {
            log.info("Ключ с kid '{}' не найден в кэше, принудительно обновляем JWKS", kid);
            jwkSet = getJwkSet(true);
            jwk = jwkSet.getKeyByKeyId(kid);
        }

        if (jwk == null) {
            return VerifyTokenResponse.failure(alg, kid,
                    "Ключ с kid '" + kid + "' не найден в публичном наборе JWKS");
        }

        if (!(jwk instanceof RSAKey rsaKey)) {
            return VerifyTokenResponse.failure(alg, kid,
                    "Тип ключа '" + jwk.getKeyType() + "' не поддерживается (ожидается RSA)");
        }

        try {
            RSASSAVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
            boolean signatureValid = signedJWT.verify(verifier);

            if (!signatureValid) {
                return VerifyTokenResponse.failure(alg, kid,
                        "Криптографическая подпись токена не совпадает (поддельный или повреждённый токен)");
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
            Date now = new Date();

            // Проверка exp
            Date expirationTime = claimsSet.getExpirationTime();
            if (expirationTime != null && now.after(expirationTime)) {
                return VerifyTokenResponse.failure(alg, kid,
                        "Срок действия токена истёк (истёк " + expirationTime + ")");
            }

            // Проверка nbf
            Date notBeforeTime = claimsSet.getNotBeforeTime();
            if (notBeforeTime != null && now.before(notBeforeTime)) {
                return VerifyTokenResponse.failure(alg, kid,
                        "Токен ещё не вступил в силу (not before " + notBeforeTime + ")");
            }

            String issuer = claimsSet.getIssuer();
            String subject = claimsSet.getSubject();
            Map<String, Object> claims = claimsSet.toJSONObject();

            return VerifyTokenResponse.success(
                    alg,
                    kid,
                    issuer,
                    subject,
                    claims,
                    "Криптографическая подпись токена успешно проверена через публичный JWKS (" + alg + ")"
            );
        } catch (Exception e) {
            log.error("Ошибка при проверке подписи токена (kid={}): {}", kid, e.getMessage(), e);
            return VerifyTokenResponse.failure(alg, kid, "Ошибка верификации подписи: " + e.getMessage());
        }
    }
}
