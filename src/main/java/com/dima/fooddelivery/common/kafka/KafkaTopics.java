package com.dima.fooddelivery.common.kafka;

import com.dima.fooddelivery.contracts.audit.AuditTopics;

/**
 * Топики сервиса пользователей. Он только пишет, и только в один — журнал аудита, который
 * собирает insights-service. Читать ему из Kafka нечего, поэтому и топика разбора нет.
 */
public final class KafkaTopics {

    public static final String AUDIT_EVENTS = AuditTopics.AUDIT_EVENTS;

    private KafkaTopics() {
    }
}
