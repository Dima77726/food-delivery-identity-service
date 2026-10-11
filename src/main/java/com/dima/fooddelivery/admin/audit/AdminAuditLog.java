package com.dima.fooddelivery.admin.audit;

import com.dima.fooddelivery.common.security.CurrentUser;
import com.dima.fooddelivery.common.web.RequestContext;
import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.persistence.AppUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Журнал административных действий над пользователями.
 *
 * <p>Схема записи та же, что у журнала аудита монолита: кто, что, над чем, с какой меткой
 * запроса. Отдельная таблица в базе этого сервиса, потому что действие и запись о нём обязаны
 * фиксироваться в одной транзакции, — а общей транзакции с базой монолита у сервиса нет и
 * быть не может.
 *
 * <p>Читает журнал администратор не здесь, а в сводном журнале insights-service: туда
 * записи этой таблицы и журнала order-service уезжают через Kafka — см.
 * {@link AuditLogPublisher}. Таблица остаётся источником истины и очередью на отправку.
 */
@Component
@RequiredArgsConstructor
public class AdminAuditLog {

    private final JdbcTemplate jdbcTemplate;
    private final AppUserRepository appUserRepository;
    private final CurrentUser currentUser;

    @Transactional
    public void record(String action, String resourceType, String resourceId, String details) {
        Long actorId = currentUser.id().orElse(null);

        // E-mail на момент действия: пользователя могут переименовать или удалить,
        // а запись журнала обязана остаться читаемой.
        String actorEmail = actorId == null
                ? null
                : appUserRepository.findById(actorId).map(AppUser::getEmail).orElse(null);

        jdbcTemplate.update(
                """
                        INSERT INTO audit_log (
                            actor_id, actor_email, action, resource_type, resource_id,
                            outcome, details, correlation_id
                        )
                        VALUES (?, ?, ?, ?, ?, 'SUCCESS', ?, ?)
                        """,
                actorId,
                actorEmail,
                action,
                resourceType,
                resourceId,
                details,
                RequestContext.correlationId().orElse(null)
        );
    }
}
