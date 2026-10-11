package com.dima.fooddelivery.user.api;

import com.dima.fooddelivery.support.AbstractIntegrationTest;
import com.dima.fooddelivery.user.service.UserService;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import jakarta.persistence.EntityManager;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Проверяет цепочку фильтров Spring Security через HTTP.
 *
 * <p>Тесты сервисов сюда не достают: {@code @PreAuthorize} висит на контроллерах, и вызов
 * сервиса напрямую его не задействует. Поэтому реальную защиту эндпоинтов можно проверить
 * только запросом.
 */
@AutoConfigureMockMvc
class AuthApiIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private EntityManager entityManager;

    @Autowired
    private UserService userService;

    @Test
    void shouldRegisterAndReturnToken() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(uniqueEmail(), "CUSTOMER")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.user.roles[0]").value("CUSTOMER"))
                // Хеш пароля не должен попасть в ответ ни при каких обстоятельствах.
                .andExpect(jsonPath("$.user.passwordHash").doesNotExist());
    }

    @Test
    void shouldRejectSelfRegistrationAsAdmin() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(uniqueEmail(), "ADMIN")))
                .andExpect(status().isConflict());
    }

    @Test
    void shouldRejectLoginWithWrongPassword() throws Exception {
        String email = uniqueEmail();

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(email, "CUSTOMER")))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "wrong-password"}
                                """.formatted(email)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectUnauthenticatedAccessToProtectedEndpoint() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldForbidCustomerFromReachingAdminApi() throws Exception {
        String token = registerAndGetToken(uniqueEmail());

        mockMvc.perform(get("/api/v1/admin/users")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    /** Токен называет того, кто зарегистрировался: {@code /auth/me} отвечает его же данными. */
    @Test
    void shouldReturnCurrentUserByToken() throws Exception {
        String email = uniqueEmail();
        String token = registerAndGetToken(email);

        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.id").value(userIdFromToken(token)));
    }

    /** Заблокированный пользователь войти не может, даже с верным паролем. */
    @Test
    void shouldRejectLoginOfDisabledUser() throws Exception {
        String email = uniqueEmail();
        registerAndGetToken(email);

        jdbcTemplate.update("UPDATE app_user SET is_enabled = FALSE WHERE LOWER(email) = LOWER(?)", email);
        // Блокировка сделана SQL в обход Hibernate, а пользователь, загруженный при регистрации,
        // остался в контексте персистентности этой же транзакции. Без очистки вход прочитал бы
        // его оттуда — включённым — и тест проверял бы кэш, а не блокировку.
        entityManager.clear();

        mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "password123"}
                                """.formatted(email)))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldIssueRefreshTokenOnRegistration() throws Exception {
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(uniqueEmail(), "CUSTOMER")))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshExpiresInSeconds").isNumber());
    }

    /** Обмен даёт новую пару, и новый access-токен рабочий. */
    @Test
    void shouldExchangeRefreshTokenForNewPair() throws Exception {
        String email = uniqueEmail();
        String refreshToken = JsonPath.read(register(email), "$.refreshToken");

        String body = refresh(refreshToken)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.email").value(email))
                .andReturn().getResponse().getContentAsString();

        String newRefreshToken = JsonPath.read(body, "$.refreshToken");
        String newAccessToken = JsonPath.read(body, "$.accessToken");

        assertThat(newRefreshToken).isNotEqualTo(refreshToken);

        mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email));
    }

    /**
     * Повторное предъявление уже обменянного токена — признак кражи: отклоняется он сам
     * и вся цепочка, включая токен, выданный при первом обмене.
     */
    @Test
    void shouldRevokeWholeSessionWhenRefreshTokenIsReused() throws Exception {
        String refreshToken = JsonPath.read(register(uniqueEmail()), "$.refreshToken");

        String body = refresh(refreshToken)
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String rotatedToken = JsonPath.read(body, "$.refreshToken");

        refresh(refreshToken).andExpect(status().isUnauthorized());
        refresh(rotatedToken).andExpect(status().isUnauthorized());
    }

    /** Выход завершает только свою сессию: вход с другого устройства остаётся живым. */
    @Test
    void shouldRevokeOnlyCurrentSessionOnLogout() throws Exception {
        String email = uniqueEmail();
        String firstDevice = JsonPath.read(register(email), "$.refreshToken");
        String secondDevice = JsonPath.read(login(email), "$.refreshToken");

        mockMvc.perform(post("/api/v1/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(refreshJson(firstDevice)))
                .andExpect(status().isNoContent());

        refresh(firstDevice).andExpect(status().isUnauthorized());
        refresh(secondDevice).andExpect(status().isOk());
    }

    @Test
    void shouldRejectUnknownRefreshToken() throws Exception {
        refresh("not-a-real-token").andExpect(status().isUnauthorized());
    }

    /** Блокировка администратором отзывает все сессии пользователя. */
    @Test
    void shouldRevokeSessionsOfDisabledUser() throws Exception {
        String email = uniqueEmail();
        String body = register(email);
        String refreshToken = JsonPath.read(body, "$.refreshToken");
        long userId = ((Number) JsonPath.read(body, "$.user.id")).longValue();

        userService.setEnabled(userId, false);

        refresh(refreshToken).andExpect(status().isUnauthorized());
    }

    private String register(String email) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(email, "CUSTOMER")))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private String login(String email) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email": "%s", "password": "password123"}
                                """.formatted(email)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
    }

    private ResultActions refresh(String refreshToken) throws Exception {
        return mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(refreshJson(refreshToken)));
    }

    private String refreshJson(String refreshToken) {
        return """
                {"refreshToken": "%s"}
                """.formatted(refreshToken);
    }

    private String registerAndGetToken(String email) throws Exception {
        String body = mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson(email, "CUSTOMER")))
                .andExpect(status().isCreated())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return JsonPath.read(body, "$.accessToken");
    }

    private long userIdFromToken(String token) throws Exception {
        String body = mockMvc.perform(get("/api/v1/auth/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        return ((Number) JsonPath.read(body, "$.id")).longValue();
    }

    private String registrationJson(String email, String role) {
        return """
                {
                  "email": "%s",
                  "password": "password123",
                  "fullName": "Тестовый Пользователь",
                  "phone": "+70000000000",
                  "role": "%s"
                }
                """.formatted(email, role);
    }

    private String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.test";
    }
}
