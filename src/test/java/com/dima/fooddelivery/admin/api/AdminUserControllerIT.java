package com.dima.fooddelivery.admin.api;

import com.dima.fooddelivery.common.security.JwtIssuer;
import com.dima.fooddelivery.support.AbstractIntegrationTest;
import com.dima.fooddelivery.user.domain.UserRole;
import com.dima.fooddelivery.user.persistence.AppUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Администрирование пользователей и его след в журнале.
 *
 * <p>Журнал аудита пользователей живёт здесь, а не в монолите, и проверяется отдельно:
 * действие и запись о нём обязаны лечь в одну транзакцию в одной базе.
 */
@AutoConfigureMockMvc
class AdminUserControllerIT extends AbstractIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtIssuer jwtIssuer;

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void shouldGrantRoleAndRecordItInAuditLog() throws Exception {
        Long adminId = testData.insertUser("admin", UserRole.ADMIN);
        Long userId = testData.insertCustomer();

        mockMvc.perform(post("/api/v1/admin/users/{id}/roles/{role}", userId, "COURIER")
                        .header("Authorization", "Bearer " + tokenFor(adminId))
                        .header("X-Correlation-Id", "admin-audit-check"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles").value(org.hamcrest.Matchers.hasItem("COURIER")));

        Map<String, Object> entry = jdbcTemplate.queryForMap(
                "SELECT actor_id, actor_email, action, resource_id, correlation_id FROM audit_log WHERE resource_id = ?",
                String.valueOf(userId)
        );

        assertAll(
                () -> assertEquals(adminId, ((Number) entry.get("actor_id")).longValue()),
                () -> assertEquals("GRANT_ROLE", entry.get("action")),
                () -> assertEquals("admin-audit-check", entry.get("correlation_id")),
                () -> assertEquals(
                        appUserRepository.findById(adminId).orElseThrow().getEmail(),
                        entry.get("actor_email"),
                        "e-mail администратора фиксируется на момент действия"
                )
        );
    }

    @Test
    void shouldNotLetCustomerGrantRoles() throws Exception {
        Long customerId = testData.insertCustomer();

        mockMvc.perform(post("/api/v1/admin/users/{id}/roles/{role}", customerId, "ADMIN")
                        .header("Authorization", "Bearer " + tokenFor(customerId)))
                .andExpect(status().isForbidden());
    }

    private String tokenFor(Long userId) {
        return jwtIssuer.issue(appUserRepository.findById(userId).orElseThrow()).token();
    }
}
