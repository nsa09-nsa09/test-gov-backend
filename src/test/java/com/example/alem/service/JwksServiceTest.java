package com.example.alem.service;

import com.example.alem.dto.VerifyTokenResponse;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class JwksServiceTest {

    private JwksService jwksService;
    private RSAKey rsaKey;
    private String keyId;

    @BeforeEach
    void setUp() throws Exception {
        jwksService = new JwksService();
        keyId = UUID.randomUUID().toString();
        rsaKey = new RSAKeyGenerator(2048)
                .keyID(keyId)
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
        AtomicReference<JWKSet> cachedRef = new AtomicReference<>(jwkSet);
        ReflectionTestUtils.setField(jwksService, "cachedJwkSet", cachedRef);
        ReflectionTestUtils.setField(jwksService, "jwkSetExpiry", System.currentTimeMillis() + 3600_000);
    }

    @Test
    void verifyIdToken_withValidToken_returnsSuccess() throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user-123")
                .issuer("http://localhost:8180/realms/GovApps")
                .audience("test-app")
                .claim("preferred_username", "testuser")
                .claim("email", "test@example.com")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey.toRSAPrivateKey()));
        String tokenStr = signedJWT.serialize();

        VerifyTokenResponse response = jwksService.verifyIdToken(tokenStr);

        assertThat(response.valid()).isTrue();
        assertThat(response.algorithm()).isEqualTo("RS256");
        assertThat(response.keyId()).isEqualTo(keyId);
        assertThat(response.subject()).isEqualTo("user-123");
        assertThat(response.issuer()).isEqualTo("http://localhost:8180/realms/GovApps");
        assertThat(response.claims()).containsEntry("preferred_username", "testuser");
        assertThat(response.claims()).containsEntry("email", "test@example.com");
    }

    @Test
    void verifyIdToken_withExpiredToken_returnsFailure() throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user-123")
                .issuer("http://localhost:8180/realms/GovApps")
                .issueTime(Date.from(Instant.now().minus(2, ChronoUnit.HOURS)))
                .expirationTime(Date.from(Instant.now().minus(1, ChronoUnit.HOURS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey.toRSAPrivateKey()));
        String tokenStr = signedJWT.serialize();

        VerifyTokenResponse response = jwksService.verifyIdToken(tokenStr);

        assertThat(response.valid()).isFalse();
        assertThat(response.message()).containsIgnoringCase("истёк");
    }

    @Test
    void verifyIdToken_withTamperedSignature_returnsFailure() throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user-123")
                .issuer("http://localhost:8180/realms/GovApps")
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(rsaKey.toRSAPrivateKey()));
        String tokenStr = signedJWT.serialize();

        // Повреждаем подпись (меняем последний символ)
        String tamperedToken = tokenStr.substring(0, tokenStr.length() - 4) + "XXXX";

        VerifyTokenResponse response = jwksService.verifyIdToken(tamperedToken);

        assertThat(response.valid()).isFalse();
        assertThat(response.message()).containsIgnoringCase("не совпадает");
    }

    @Test
    void verifyIdToken_withUnknownKeyId_returnsFailure() throws Exception {
        RSAKey anotherKey = new RSAKeyGenerator(2048)
                .keyID("unknown-kid")
                .algorithm(JWSAlgorithm.RS256)
                .generate();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("user-123")
                .expirationTime(Date.from(Instant.now().plus(1, ChronoUnit.HOURS)))
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("unknown-kid").build(),
                claimsSet
        );
        signedJWT.sign(new RSASSASigner(anotherKey.toRSAPrivateKey()));
        String tokenStr = signedJWT.serialize();

        VerifyTokenResponse response = jwksService.verifyIdToken(tokenStr);

        assertThat(response.valid()).isFalse();
        assertThat(response.message()).contains("не найден");
    }
}
