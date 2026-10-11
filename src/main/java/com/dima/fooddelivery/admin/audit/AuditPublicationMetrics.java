package com.dima.fooddelivery.admin.audit;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Сколько записей журнала ещё не уехало в сводный журнал. Растёт и не убывает — отправка
 * встала: брокер недоступен или таймер не запущен. Имя метрики общее с order-service,
 * различает их тег {@code application}.
 */
@Slf4j
@Component
public class AuditPublicationMetrics {

    private final AuditLogPublisher auditLogPublisher;

    public AuditPublicationMetrics(MeterRegistry registry, AuditLogPublisher auditLogPublisher) {
        this.auditLogPublisher = auditLogPublisher;

        Gauge.builder("food_delivery.audit.backlog", this, AuditPublicationMetrics::countQuietly)
                .description("Записей журнала аудита ожидает отправки в сводный журнал")
                .register(registry);
    }

    /** NaN, а не ноль, при недоступной базе: ноль выглядел бы как «очередь пуста». */
    private double countQuietly() {
        try {
            return auditLogPublisher.countUnpublished();
        } catch (RuntimeException exception) {
            log.warn("Не удалось посчитать неотправленный журнал аудита: {}", exception.getMessage());

            return Double.NaN;
        }
    }
}
