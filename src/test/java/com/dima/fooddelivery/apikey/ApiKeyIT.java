package com.dima.fooddelivery.apikey;

import com.dima.fooddelivery.support.AbstractIntegrationTest;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Ключи API: выпуск, обмен на токен, отзыв и то, чего ключом делать нельзя. */
@AutoConfigureMockMvc
class ApiKeyIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private JwtDecoder jwtDecoder;

    @Test
    void shouldIssueKeyAndExchangeItForOwnerToken() throws Exception {
        Owner owner = registerOwner();
        String key = createKey(owner.token(), "Касса");

        assertTrue(key.matches("^fdp_[a-z0-9]{8}_[A-Za-z0-9]{32}$"), key);

        String body = mockMvc.perform(post("/api/v1/auth/api-keys/token").header("X-Api-Key", key))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.refreshToken").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        var jwt = jwtDecoder.decode(JsonPath.read(body, "$.accessToken"));
        assertEquals(String.valueOf(owner.id()), jwt.getSubject());
        assertTrue(jwt.getClaimAsStringList("roles").contains("RESTAURANT_OWNER"));
        assertTrue(jwt.hasClaim("api_key_id"));
    }

    @Test
    void shouldStoreOnlyHashOfSecret() throws Exception {
        Owner owner = registerOwner();
        String key = createKey(owner.token(), "Касса");
        String secret = key.substring(key.lastIndexOf('_') + 1);

        String stored = jdbcTemplate.queryForObject(
                "SELECT secret_hash FROM partner_api_key WHERE user_id = ?", String.class, owner.id());

        assertFalse(stored.contains(secret));
        assertEquals(ApiKeyService.sha256(secret), stored);

        mockMvc.perform(get("/api/v1/auth/api-keys").header("Authorization", "Bearer " + owner.token()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].prefix").value(key.substring(0, 12)))
                .andExpect(jsonPath("$[0].key").doesNotExist());
    }

    @Test
    void shouldRejectRevokedForgedAndMalformedKeys() throws Exception {
        Owner owner = registerOwner();
        String key = createKey(owner.token(), "Касса");
        long id = jdbcTemplate.queryForObject("SELECT id FROM partner_api_key WHERE user_id = ?", Long.class, owner.id());

        String forged = key.substring(0, key.length() - 1) + (key.endsWith("A") ? "B" : "A");
        mockMvc.perform(post("/api/v1/auth/api-keys/token").header("X-Api-Key", forged)).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/v1/auth/api-keys/token").header("X-Api-Key", "garbage")).andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/v1/auth/api-keys/token")).andExpect(status().isUnauthorized());

        mockMvc.perform(delete("/api/v1/auth/api-keys/{id}", id).header("Authorization", "Bearer " + owner.token()))
                .andExpect(status().isNoContent());
        mockMvc.perform(post("/api/v1/auth/api-keys/token").header("X-Api-Key", key)).andExpect(status().isUnauthorized());
    }

    @Test
    void shouldNotLetKeyTokenManageKeys() throws Exception {
        Owner owner = registerOwner();
        String key = createKey(owner.token(), "Касса");
        String keyToken = JsonPath.read(mockMvc.perform(post("/api/v1/auth/api-keys/token").header("X-Api-Key", key))
                .andReturn().getResponse().getContentAsString(), "$.accessToken");

        mockMvc.perform(post("/api/v1/auth/api-keys")
                        .header("Authorization", "Bearer " + keyToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"ещё один\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldNotLetCustomerIssueKeys() throws Exception {
        String customer = register("CUSTOMER");

        mockMvc.perform(post("/api/v1/auth/api-keys")
                        .header("Authorization", "Bearer " + customer)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"ключ\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldNotRevokeSomeoneElsesKey() throws Exception {
        Owner owner = registerOwner();
        Owner other = registerOwner();
        createKey(owner.token(), "Касса");
        long id = jdbcTemplate.queryForObject("SELECT id FROM partner_api_key WHERE user_id = ?", Long.class, owner.id());

        mockMvc.perform(delete("/api/v1/auth/api-keys/{id}", id).header("Authorization", "Bearer " + other.token()))
                .andExpect(status().isNotFound());
    }

    private String createKey(String token, String name) throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/api-keys")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"" + name + "\"}"))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.key");
    }

    private Owner registerOwner() throws Exception {
        String token = register("RESTAURANT_OWNER");
        long id = ((Number) JsonPath.read(mockMvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token))
                .andReturn().getResponse().getContentAsString(), "$.id")).longValue();
        return new Owner(id, token);
    }

    private String register(String role) throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"%s","password":"password123","fullName":"Партнёр","phone":"+70000000000","role":"%s"}
                                """.formatted("partner-" + UUID.randomUUID() + "@example.test", role)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.accessToken");
    }

    private record Owner(long id, String token) {
    }
}
