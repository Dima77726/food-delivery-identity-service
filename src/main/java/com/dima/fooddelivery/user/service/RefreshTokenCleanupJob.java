package com.dima.fooddelivery.user.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Удаляет истёкшие refresh-токены, иначе таблица растёт на строку при каждом обмене.
 */
@Slf4j
@Component
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.auth.refresh-token-cleanup-enabled", havingValue = "true", matchIfMissing = true)
public class RefreshTokenCleanupJob {

    private final RefreshTokenService refreshTokenService;

    @Scheduled(fixedDelayString = "${app.auth.refresh-token-cleanup-interval:PT1H}")
    public void cleanup() {
        int deleted = refreshTokenService.deleteExpired();

        if (deleted > 0) {
            log.info("Удалено истёкших refresh-токенов: {}", deleted);
        }
    }
}
