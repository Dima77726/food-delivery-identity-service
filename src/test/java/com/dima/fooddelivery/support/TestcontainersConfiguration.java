package com.dima.fooddelivery.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.testcontainers.kafka.ConfluentKafkaContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Настоящий PostgreSQL и Kafka для тестов сервиса пользователей. Никого из сервисов он
 * не вызывает; Kafka нужна только журналу аудита, который уезжает в сводный журнал.
 */
@TestConfiguration(proxyBeanMethods = false)
public class TestcontainersConfiguration {

    @Bean
    @ServiceConnection
    PostgreSQLContainer postgresContainer() {
        return new PostgreSQLContainer("postgres:16");
    }

    /**
     * Образ Confluent, а не apache/kafka из compose, — по той же причине, что в order-service:
     * с apache/kafka Testcontainers не стартует (см. там же).
     */
    @Bean
    @ServiceConnection
    ConfluentKafkaContainer kafkaContainer() {
        return new ConfluentKafkaContainer("confluentinc/cp-kafka:7.8.0");
    }

    @Bean
    TestDataFactory testDataFactory(JdbcTemplate jdbcTemplate) {
        return new TestDataFactory(jdbcTemplate);
    }
}
