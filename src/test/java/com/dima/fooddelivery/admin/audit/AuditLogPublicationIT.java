package com.dima.fooddelivery.admin.audit;

import com.dima.fooddelivery.common.kafka.KafkaTopics;
import com.dima.fooddelivery.contracts.audit.AuditEvent;
import com.dima.fooddelivery.support.AbstractIntegrationTest;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.clients.consumer.ConsumerRecord;
import org.apache.kafka.clients.consumer.KafkaConsumer;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.kafka.ConfluentKafkaContainer;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Журнал административных действий уезжает в топик сводного журнала и получает отметку.
 *
 * <p>Без транзакции теста: публикатор видит только зафиксированное. Запись вставляется
 * SQL-запросом, а не через {@link AdminAuditLog}: здесь проверяется доставка, а то, что
 * действие администратора пишет журнал, проверяет {@code AdminUserControllerIT}.
 */
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class AuditLogPublicationIT extends AbstractIntegrationTest {

    private static final Duration DELIVERY_TIMEOUT = Duration.ofSeconds(30);

    @Autowired
    private AuditLogPublisher auditLogPublisher;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ConfluentKafkaContainer kafkaContainer;

    @Test
    void shouldPublishEntryKeyedByUserAndMarkIt() {
        Long adminId = testData.insertUser("admin");
        String userId = String.valueOf(testData.insertCustomer());

        try (KafkaConsumer<String, String> consumer = createConsumer()) {
            Long id = jdbcTemplate.queryForObject(
                    """
                            INSERT INTO audit_log (
                                actor_id, actor_email, action, resource_type, resource_id,
                                outcome, details, correlation_id
                            )
                            VALUES (?, 'admin@example.test', 'GRANT_ROLE', 'USER', ?, 'SUCCESS', 'COURIER', 'grant-check')
                            RETURNING id
                            """,
                    Long.class,
                    adminId,
                    userId
            );

            drainQueue();

            ConsumerRecord<String, String> record = awaitRecord(consumer, "USER:" + userId);
            AuditEvent event = objectMapper.readValue(record.value(), AuditEvent.class);

            assertAll(
                    () -> assertEquals(AuditEvent.eventIdOf("identity-service", id), event.eventId()),
                    () -> assertEquals("identity-service", event.sourceService()),
                    () -> assertEquals(adminId, event.actorId()),
                    () -> assertEquals("admin@example.test", event.actorEmail()),
                    () -> assertEquals("GRANT_ROLE", event.action()),
                    () -> assertEquals("grant-check", event.correlationId()),
                    () -> assertNotNull(
                            jdbcTemplate.queryForObject("SELECT published_at FROM audit_log WHERE id = ?", Object.class, id),
                            "подтверждённая запись обязана получить отметку"
                    ),
                    () -> assertEquals(0L, auditLogPublisher.countUnpublished(), "очередь после отправки пуста")
            );
        }
    }

    /** Пачки ограничены, а неотправленные записи могли оставить другие тесты. */
    private void drainQueue() {
        for (int round = 0; round < 50; round++) {
            if (auditLogPublisher.publishBatch() == 0) {
                return;
            }
        }
    }

    private KafkaConsumer<String, String> createConsumer() {
        Properties props = new Properties();

        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafkaContainer.getBootstrapServers());
        props.put(ConsumerConfig.GROUP_ID_CONFIG, "audit-assertions-" + UUID.randomUUID());
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");
        props.put(ConsumerConfig.ENABLE_AUTO_COMMIT_CONFIG, "false");

        KafkaConsumer<String, String> consumer =
                new KafkaConsumer<>(props, new StringDeserializer(), new StringDeserializer());
        consumer.subscribe(List.of(KafkaTopics.AUDIT_EVENTS));
        consumer.poll(Duration.ofSeconds(2));

        return consumer;
    }

    private ConsumerRecord<String, String> awaitRecord(KafkaConsumer<String, String> consumer, String key) {
        Instant deadline = Instant.now().plus(DELIVERY_TIMEOUT);

        while (Instant.now().isBefore(deadline)) {
            for (ConsumerRecord<String, String> record : consumer.poll(Duration.ofMillis(500))) {
                if (key.equals(record.key())) {
                    return record;
                }
            }
        }

        throw new AssertionError("Не дождались записи журнала с ключом " + key + " за " + DELIVERY_TIMEOUT);
    }
}
