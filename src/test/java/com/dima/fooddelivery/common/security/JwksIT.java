package com.dima.fooddelivery.common.security;

import com.dima.fooddelivery.support.TestcontainersConfiguration;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Токен глазами другого сервиса: проверяется только тем, что опубликовано в JWKS.
 *
 * <p>Ровно так токен проверяют монолит, каталог и сервис уведомлений: скачивают JWKS
 * по HTTP и сверяют подпись. Если этот тест проходит, они примут токен; если нет —
 * не примет никто, и узнать об этом лучше здесь, а не по 401 на каждом запросе стенда.
 *
 * <p>Сервер на настоящем порту, а не MockMvc: декодер ходит за JWKS по сети.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"management.server.port=0", "logging.level.liquibase=WARN"}
)
@Import(TestcontainersConfiguration.class)
class JwksIT {

    @LocalServerPort
    private int port;

    @Test
    void shouldIssueTokenVerifiableWithPublishedKeysOnly() {
        String email = "jwks-" + UUID.randomUUID() + "@example.test";
        String registration = http().post()
                .uri("/api/v1/auth/register")
                .contentType(MediaType.APPLICATION_JSON)
                .body("""
                        {"email": "%s", "password": "password123", "fullName": "JWKS", "role": "CUSTOMER"}
                        """.formatted(email))
                .retrieve()
                .body(String.class);

        String token = JsonPath.read(registration, "$.accessToken");
        long userId = ((Number) JsonPath.read(registration, "$.user.id")).longValue();

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(baseUrl() + "/.well-known/jwks.json")
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();

        Jwt jwt = decoder.decode(token);

        assertAll(
                () -> assertEquals(String.valueOf(userId), jwt.getSubject()),
                () -> assertEquals(email, jwt.getClaimAsString("email")),
                () -> assertEquals(List.of("CUSTOMER"), jwt.getClaimAsStringList("roles")),
                () -> assertEquals("food-delivery-platform", jwt.getClaimAsString("iss")),
                () -> assertEquals("test-key", jwt.getHeaders().get("kid"), "по kid проверяющий выбирает ключ"),
                () -> assertEquals("RS256", jwt.getHeaders().get("alg"))
        );
    }

    /**
     * Самая важная проверка этого класса: закрытая часть ключа не публикуется. Попади
     * в JWKS поле {@code d} — и любой, кто открыл эту страницу, может выпустить себе
     * токен администратора.
     */
    @Test
    @SuppressWarnings("unchecked")
    void shouldPublishOnlyPublicPartOfKey() {
        Map<String, Object> jwks = http().get().uri("/.well-known/jwks.json").retrieve().body(Map.class);

        Map<String, Object> key = ((List<Map<String, Object>>) jwks.get("keys")).get(0);

        assertAll(
                () -> assertEquals("RSA", key.get("kty")),
                () -> assertEquals("test-key", key.get("kid")),
                () -> assertFalse(key.containsKey("d"), "закрытая экспонента не должна публиковаться"),
                () -> assertFalse(key.containsKey("p"), "множители закрытого ключа не должны публиковаться"),
                () -> assertFalse(key.containsKey("q"), "множители закрытого ключа не должны публиковаться")
        );
    }

    private RestClient http() {
        return RestClient.create(baseUrl());
    }

    private String baseUrl() {
        return "http://localhost:" + port;
    }
}
