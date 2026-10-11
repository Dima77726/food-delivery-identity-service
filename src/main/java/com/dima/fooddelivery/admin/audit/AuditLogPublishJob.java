package com.dima.fooddelivery.admin.audit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Запускает отправку журнала по расписанию. Отдельный бин — чтобы вызов шёл через прокси
 * транзакции и чтобы выключатель гасил только таймер, а не публикатор: тесты вызывают его сами.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.audit.publish-enabled", havingValue = "true", matchIfMissing = true)
public class AuditLogPublishJob {

    private final AuditLogPublisher auditLogPublisher;

    @Scheduled(fixedDelayString = "${app.audit.publish-interval:PT5S}")
    public void publish() {
        int published = auditLogPublisher.publishBatch();

        if (published > 0) {
            log.debug("Отправлено в сводный журнал аудита: {}", published);
        }
    }
}
