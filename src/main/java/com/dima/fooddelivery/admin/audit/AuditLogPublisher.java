package com.dima.fooddelivery.admin.audit;

import com.dima.fooddelivery.common.kafka.KafkaTopics;
import com.dima.fooddelivery.common.web.RequestContext;
import com.dima.fooddelivery.contracts.audit.AuditEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Отправляет журнал административных действий в сводный журнал insights-service.
 *
 * <p>Устроен так же, как {@code AuditPublisher} в order-service, и по тем же причинам —
 * пояснения там. Коротко: таблица журнала служит outbox, пачка берётся под
 * {@code FOR UPDATE SKIP LOCKED}, отправляется целиком, отметка {@code published_at}
 * ставится только подтверждённым записям. Доставка «хотя бы один раз», повтор узнаётся
 * по {@code eventId}, выведенному из номера записи.
 *
 * <p>Код не вынесен в общую библиотеку намеренно: публикатор — это двадцать строк SQL
 * и цикл, а общая библиотека связала бы два сервиса версией, схемой таблицы и выбором
 * слоя доступа к данным (там голый JDBC, здесь JdbcTemplate).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AuditLogPublisher {

    /** Имя источника в сводном журнале; из него выводится {@code eventId}, поэтому константа. */
    static final String SOURCE_SERVICE = "identity-service";

    private static final int BATCH_SIZE = 100;

    private static final Duration SEND_TIMEOUT = Duration.ofSeconds(10);

    private static final RowMapper<AuditEvent> AUDIT_EVENT = (rs, rowNum) -> {
        long id = rs.getLong("id");

        return new AuditEvent(
                AuditEvent.eventIdOf(SOURCE_SERVICE, id),
                AuditEvent.CURRENT_SCHEMA_VERSION,
                SOURCE_SERVICE,
                id,
                // getObject с классом: getLong вернул бы 0 вместо NULL у системного действия.
                rs.getObject("actor_id", Long.class),
                rs.getString("actor_email"),
                rs.getString("action"),
                rs.getString("resource_type"),
                rs.getString("resource_id"),
                rs.getString("outcome"),
                rs.getString("details"),
                rs.getString("correlation_id"),
                rs.getObject("created_at", OffsetDateTime.class)
        );
    };

    private final JdbcTemplate jdbcTemplate;
    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    /** @return сколько записей подтверждено и отмечено */
    @Transactional
    public int publishBatch() {
        List<AuditEvent> pending = jdbcTemplate.query(
                """
                        SELECT id, actor_id, actor_email, action, resource_type, resource_id,
                               outcome, details, correlation_id, created_at
                        FROM audit_log
                        WHERE published_at IS NULL
                        ORDER BY id
                        LIMIT ?
                        FOR UPDATE SKIP LOCKED
                        """,
                AUDIT_EVENT,
                BATCH_SIZE
        );

        if (pending.isEmpty()) {
            return 0;
        }

        List<CompletableFuture<SendResult<String, String>>> sends = new ArrayList<>(pending.size());
        for (AuditEvent event : pending) {
            sends.add(kafkaTemplate.send(toProducerRecord(event)));
        }

        List<Long> confirmed = awaitConfirmed(pending, sends);

        if (!confirmed.isEmpty()) {
            jdbcTemplate.update(
                    """
                            UPDATE audit_log
                            SET published_at = CURRENT_TIMESTAMP
                            WHERE id = ANY (?)
                              AND published_at IS NULL
                            """,
                    (Object) confirmed.toArray(Long[]::new)
            );
        }

        return confirmed.size();
    }

    public long countUnpublished() {
        Long count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM audit_log WHERE published_at IS NULL",
                Long.class
        );

        return count == null ? 0L : count;
    }

    private List<Long> awaitConfirmed(
            List<AuditEvent> pending,
            List<CompletableFuture<SendResult<String, String>>> sends
    ) {
        Instant deadline = Instant.now().plus(SEND_TIMEOUT);
        List<Long> confirmed = new ArrayList<>(pending.size());

        for (int i = 0; i < pending.size(); i++) {
            AuditEvent event = pending.get(i);

            try {
                long remainingMillis = Math.max(0, Duration.between(Instant.now(), deadline).toMillis());
                sends.get(i).get(remainingMillis, TimeUnit.MILLISECONDS);

                confirmed.add(event.sourceId());
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();

                return confirmed;
            } catch (Exception exception) {
                log.warn(
                        "Запись журнала аудита не отправлена: auditId={}, correlationId={}, reason={}",
                        event.sourceId(),
                        event.correlationId(),
                        exception.getMessage()
                );
            }
        }

        return confirmed;
    }

    /** Ключ — ресурс ({@code USER:7}): записи об одном пользователе идут по порядку. */
    private ProducerRecord<String, String> toProducerRecord(AuditEvent event) {
        ProducerRecord<String, String> record = new ProducerRecord<>(
                KafkaTopics.AUDIT_EVENTS,
                event.resourceId() == null ? event.resourceType() : event.resourceType() + ":" + event.resourceId(),
                objectMapper.writeValueAsString(event)
        );

        if (event.correlationId() != null) {
            record.headers().add(
                    RequestContext.CORRELATION_ID_HEADER,
                    event.correlationId().getBytes(StandardCharsets.UTF_8)
            );
        }

        return record;
    }
}
