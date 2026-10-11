package com.dima.fooddelivery.common.kafka;

import org.apache.kafka.clients.admin.NewTopic;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;

/**
 * Kafka сервиса пользователей — только продюсер. Сообщения — строки JSON, как во всех
 * сервисах: тело собирает публикатор, сериализатор ничего от себя не добавляет.
 */
@Configuration(proxyBeanMethods = false)
public class KafkaConfig {

    /**
     * Топик объявляют все, кто в него пишет или читает: объявление идемпотентно, а стартовать
     * первым может любой. Параметры у всех одинаковые — три партиции, ключ по ресурсу.
     */
    @Bean
    NewTopic auditEventsTopic() {
        return TopicBuilder.name(KafkaTopics.AUDIT_EVENTS)
                .partitions(3)
                .replicas(1)
                .build();
    }
}
