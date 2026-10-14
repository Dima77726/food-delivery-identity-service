package com.dima.fooddelivery.federation;

import com.dima.fooddelivery.support.AbstractIntegrationTest;
import com.dima.fooddelivery.user.domain.UserRole;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.sun.net.httpserver.HttpServer;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.dima.fooddelivery.federation.OidcTokenVerifierTest.claims;
import static com.dima.fooddelivery.federation.OidcTokenVerifierTest.generate;
import static com.dima.fooddelivery.federation.OidcTokenVerifierTest.token;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Вход через Keycloak: обмен токена провайдера на токен платформы, целиком, по HTTP.
 *
 * <p>Ключи провайдера отдаёт настоящий HTTP-сервер по адресу JWKS — боевая сборка проверки (с загрузкой ключей
 * по сети, издателем и клиентом из настроек) работает так же, как против Keycloak. Подменён только сам провайдер.
 */
@AutoConfigureMockMvc
class FederatedLoginIT extends AbstractIntegrationTest {

    private static final String ISSUER = "http://localhost:8180/realms/food-delivery";
    private static final String CLIENT = "food-delivery-web";

    private static final RSAKey PROVIDER_KEY = generate("provider-key");
    private static final RSAKey ATTACKER_KEY = generate("attacker-key");

    private static final HttpServer JWKS_SERVER = startJwksServer();

    @DynamicPropertySource
    static void oidc(DynamicPropertyRegistry registry) {
        registry.add("app.oidc.enabled", () -> "true");
        registry.add("app.oidc.issuer", () -> ISSUER);
        registry.add("app.oidc.jwk-set-uri", () -> "http://localhost:" + JWKS_SERVER.getAddress().getPort() + "/certs");
        registry.add("app.oidc.client-ids", () -> CLIENT);
    }

    @AfterAll
    static void stop() {
        JWKS_SERVER.stop(0);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private EntityManager entityManager;

    @Test
    void shouldCreateUserOnFirstLoginWithGrantableRolesOnly() throws Exception {
        String email = uniqueEmail();
        String subject = UUID.randomUUID().toString();
        // ADMIN у провайдера - не повод делать человека администратором платформы.
        String token = providerToken(subject, email, List.of("COURIER", "ADMIN"));

        MvcResult result = exchange(token).andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.user.email").value(email))
                .andReturn();

        Long userId = jdbc.queryForObject("SELECT id FROM app_user WHERE LOWER(email) = LOWER(?)", Long.class, email);
        List<String> roles = jdbc.queryForList("SELECT role FROM app_user_role WHERE user_id = ?", String.class, userId);

        assertAll(
                () -> assertEquals(List.of("COURIER"), roles),
                () -> assertEquals(1, jdbc.queryForObject(
                        "SELECT COUNT(*) FROM external_identity WHERE issuer = ? AND subject = ?", Integer.class, ISSUER, subject)),
                () -> assertTrue(result.getResponse().getContentAsString().contains("\"COURIER\""))
        );
    }

    @Test
    void shouldGiveCustomerRoleWhenProviderSendsNoGrantableRole() throws Exception {
        String email = uniqueEmail();

        exchange(providerToken(UUID.randomUUID().toString(), email, List.of())).andExpect(status().isOk());

        assertEquals(List.of("CUSTOMER"), jdbc.queryForList(
                "SELECT r.role FROM app_user_role r JOIN app_user u ON u.id = r.user_id WHERE LOWER(u.email) = LOWER(?)",
                String.class, email));
    }

    @Test
    void shouldIssuePlatformTokenThatWorksOnTheApi() throws Exception {
        String email = uniqueEmail();
        MvcResult result = exchange(providerToken(UUID.randomUUID().toString(), email, List.of("CUSTOMER")))
                .andExpect(status().isOk()).andReturn();

        String accessToken = com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.accessToken");

        mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));
    }

    /** Основной ключ - subject: сменив адрес у провайдера, человек остаётся тем же пользователем. */
    @Test
    void shouldRecognizeReturningUserBySubjectEvenAfterEmailChange() throws Exception {
        String subject = UUID.randomUUID().toString();
        String firstEmail = uniqueEmail();

        exchange(providerToken(subject, firstEmail, List.of("CUSTOMER"))).andExpect(status().isOk());
        Integer usersBefore = jdbc.queryForObject("SELECT COUNT(*) FROM app_user", Integer.class);

        exchange(providerToken(subject, uniqueEmail(), List.of("CUSTOMER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.email").value(firstEmail));

        assertEquals(usersBefore, jdbc.queryForObject("SELECT COUNT(*) FROM app_user", Integer.class),
                "новый пользователь появиться не должен");
    }

    @Test
    void shouldLinkExistingUserByVerifiedEmailWithoutTouchingRoles() throws Exception {
        String email = uniqueEmail();
        mockMvc.perform(post("/api/v1/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content(registration(email, "COURIER")))
                .andExpect(status().isCreated());
        entityManager.flush();

        // Провайдер называет человека клиентом, но роли платформа у существующего пользователя не меняет.
        exchange(providerToken(UUID.randomUUID().toString(), email, List.of("CUSTOMER", "RESTAURANT_OWNER")))
                .andExpect(status().isOk());

        Long userId = jdbc.queryForObject("SELECT id FROM app_user WHERE LOWER(email) = LOWER(?)", Long.class, email);

        assertAll(
                () -> assertEquals(List.of("COURIER"), jdbc.queryForList("SELECT role FROM app_user_role WHERE user_id = ?", String.class, userId)),
                () -> assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM external_identity WHERE user_id = ?", Integer.class, userId))
        );

        // Вход по паролю при этом продолжает работать.
        mockMvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + email + "\",\"password\":\"Passw0rd!x\"}"))
                .andExpect(status().isOk());
    }

    /** Администратора нельзя «захватить» подтверждённой почтой у провайдера. */
    @Test
    void shouldRefuseToLinkAdministratorAccount() throws Exception {
        Long adminId = testData.insertUser("fed-admin", UserRole.ADMIN);
        String email = jdbc.queryForObject("SELECT email FROM app_user WHERE id = ?", String.class, adminId);
        entityManager.flush();

        exchange(providerToken(UUID.randomUUID().toString(), email, List.of("CUSTOMER")))
                .andExpect(status().isUnauthorized());

        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM external_identity WHERE user_id = ?", Integer.class, adminId));
    }

    @Test
    void shouldRejectBlockedUser() throws Exception {
        String email = uniqueEmail();
        String subject = UUID.randomUUID().toString();
        exchange(providerToken(subject, email, List.of("CUSTOMER"))).andExpect(status().isOk());

        jdbc.update("UPDATE app_user SET is_enabled = FALSE WHERE LOWER(email) = LOWER(?)", email);
        entityManager.clear();

        exchange(providerToken(subject, email, List.of("CUSTOMER"))).andExpect(status().isForbidden());
    }

    @Test
    void shouldRejectUnverifiedEmailAndCreateNobody() throws Exception {
        String email = uniqueEmail();
        String token = token(PROVIDER_KEY, claims().subject(UUID.randomUUID().toString()).claim("email", email)
                .claim("email_verified", false));

        exchange(token).andExpect(status().isUnauthorized());

        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM app_user WHERE LOWER(email) = LOWER(?)", Integer.class, email));
    }

    @Test
    void shouldRejectTokenSignedByAttackerAndCreateNobody() throws Exception {
        String email = uniqueEmail();
        String token = token(ATTACKER_KEY, claims().subject(UUID.randomUUID().toString()).claim("email", email));

        exchange(token).andExpect(status().isUnauthorized());

        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM app_user WHERE LOWER(email) = LOWER(?)", Integer.class, email));
    }

    @Test
    void shouldRejectEmptyBody() throws Exception {
        mockMvc.perform(post("/api/v1/auth/oidc").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest());
    }

    // --- вспомогательное -----------------------------------------------------------------------

    private org.springframework.test.web.servlet.ResultActions exchange(String providerToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/oidc").contentType(MediaType.APPLICATION_JSON)
                .content("{\"token\":\"" + providerToken + "\"}"));
    }

    private String providerToken(String subject, String email, List<String> roles) {
        return token(PROVIDER_KEY, claims()
                .subject(subject)
                .claim("email", email)
                .claim("realm_access", Map.of("roles", roles)));
    }

    private static String registration(String email, String role) {
        return "{\"email\":\"" + email + "\",\"password\":\"Passw0rd!x\",\"fullName\":\"Test User\",\"phone\":\"+79990000000\",\"role\":\"" + role + "\"}";
    }

    private String uniqueEmail() {
        return "kc-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
    }

    private static HttpServer startJwksServer() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            byte[] body = new JWKSet(PROVIDER_KEY.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);

            server.createContext("/certs", exchange -> {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
            server.start();

            return server;
        } catch (IOException exception) {
            throw new IllegalStateException(exception);
        }
    }
}
