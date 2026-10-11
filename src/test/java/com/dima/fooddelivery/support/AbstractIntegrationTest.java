package com.dima.fooddelivery.support;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.transaction.annotation.Transactional;

/**
 * База для интеграционных тестов сервиса пользователей: настоящий PostgreSQL и миграции.
 * {@link Transactional} — откат после каждого теста.
 */
@SpringBootTest(properties = {
        // Журнал аудита тесты отправляют сами: с таймером момент отправки был бы гонкой.
        "app.audit.publish-enabled=false",
        "logging.level.liquibase=WARN",
        "logging.level.org.testcontainers=WARN",
        "logging.level.com.zaxxer.hikari=WARN"
})
@Import(TestcontainersConfiguration.class)
@Transactional
public abstract class AbstractIntegrationTest {

    @Autowired
    protected TestDataFactory testData;
}
