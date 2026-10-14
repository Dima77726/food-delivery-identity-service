package com.dima.fooddelivery.federation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Проверка токена провайдера. Главное здесь — отказы: каждая из проверок существует потому, что без неё
 * вход под чужим именем становится возможным, и каждая должна быть подтверждена тестом, а не комментарием.
 */
class OidcTokenVerifierTest {

    private static final String ISSUER = "http://localhost:8180/realms/food-delivery";
    private static final String CLIENT = "food-delivery-web";

    private static final RSAKey KEY = generate("trusted");
    private static final RSAKey OTHER_KEY = generate("attacker");

    private final OidcTokenVerifier verifier = verifierFor(KEY);

    @Test
    void shouldAcceptValidTokenAndExtractIdentity() {
        String token = token(KEY, claims().claim("realm_access", Map.of("roles", List.of("CUSTOMER", "COURIER"))));

        OidcTokenVerifier.VerifiedIdentity identity = verifier.verify(token);

        assertAll(
                () -> assertEquals(ISSUER, identity.issuer()),
                () -> assertEquals("kc-user-1", identity.subject()),
                () -> assertEquals("anna@example.com", identity.email()),
                () -> assertEquals("Анна Петрова", identity.name()),
                () -> assertEquals(Set.of("CUSTOMER", "COURIER"), identity.roles())
        );
    }

    @Test
    void shouldFallBackToUsernameAndEmailForDisplayName() {
        String withUsername = token(KEY, claims().claim("name", null).claim("preferred_username", "anna"));
        String withNothing = token(KEY, claims().claim("name", null));

        assertAll(
                () -> assertEquals("anna", verifier.verify(withUsername).name()),
                () -> assertEquals("anna@example.com", verifier.verify(withNothing).name())
        );
    }

    @Test
    void shouldIgnoreMalformedRolesClaim() {
        String token = token(KEY, claims().claim("realm_access", Map.of("roles", "ADMIN")));

        assertEquals(Set.of(), verifier.verify(token).roles());
    }

    @Test
    void shouldRejectTokenSignedWithForeignKey() {
        assertRejected(token(OTHER_KEY, claims()));
    }

    @Test
    void shouldRejectTokenFromAnotherIssuer() {
        assertRejected(token(KEY, claims().issuer("http://localhost:8180/realms/other")));
    }

    @Test
    void shouldRejectExpiredToken() {
        assertRejected(token(KEY, claims().expirationTime(Date.from(Instant.now().minusSeconds(3600)))));
    }

    /** Токен того же realm, но выданный другому приложению, не для нас. */
    @Test
    void shouldRejectTokenIssuedToAnotherClient() {
        assertRejected(token(KEY, claims().claim("azp", "some-other-app")));
    }

    @Test
    void shouldRejectTokenWithoutClient() {
        assertRejected(token(KEY, claims().claim("azp", null)));
    }

    /** Непроверенную почту принимать нельзя: по ней находится пользователь платформы. */
    @Test
    void shouldRejectUnverifiedEmail() {
        assertRejected(token(KEY, claims().claim("email_verified", false)));
        assertRejected(token(KEY, claims().claim("email_verified", null)));
    }

    @Test
    void shouldRejectMissingEmail() {
        assertRejected(token(KEY, claims().claim("email", null)));
        assertRejected(token(KEY, claims().claim("email", "  ")));
    }

    @Test
    void shouldRejectGarbageAndOversizedInput() {
        assertRejected("not-a-jwt");
        assertRejected("");
        assertRejected(null);
        assertRejected("a".repeat(9_000));
    }

    @Test
    void shouldRefuseToStartWithoutClientsOrEndpoints() {
        OidcProperties noClients = new OidcProperties(true, ISSUER, "http://localhost/jwks", List.of(), Set.of(), false, java.time.Duration.ofSeconds(1));
        OidcProperties noIssuer = new OidcProperties(true, "", "http://localhost/jwks", List.of(CLIENT), Set.of(), false, java.time.Duration.ofSeconds(1));

        assertAll(
                () -> assertThrows(IllegalStateException.class, () -> OidcTokenVerifier.from(noClients)),
                () -> assertThrows(IllegalStateException.class, () -> OidcTokenVerifier.from(noIssuer))
        );
    }

    // --- вспомогательное -----------------------------------------------------------------------

    private void assertRejected(String token) {
        assertThrows(BadCredentialsException.class, () -> verifier.verify(token));
    }

    /** Боевая сборка проверяет те же правила; здесь она собрана вокруг открытого ключа вместо JWKS по сети. */
    static OidcTokenVerifier verifierFor(RSAKey key) {
        try {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey()).build();
            decoder.setJwtValidator(OidcTokenVerifier.validators(ISSUER, Set.of(CLIENT)));

            return new OidcTokenVerifier(decoder);
        } catch (JOSEException exception) {
            throw new IllegalStateException(exception);
        }
    }

    static JWTClaimsSet.Builder claims() {
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject("kc-user-1")
                .claim("azp", CLIENT)
                .claim("email", "anna@example.com")
                .claim("email_verified", true)
                .claim("name", "Анна Петрова")
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)));
    }

    static String token(RSAKey key, JWTClaimsSet.Builder claims) {
        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),
                    claims.build()
            );
            jwt.sign(new RSASSASigner(key));

            return jwt.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException(exception);
        }
    }

    static RSAKey generate(String id) {
        try {
            return new RSAKeyGenerator(2048).keyID(id).generate();
        } catch (JOSEException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
