package com.dima.fooddelivery.federation;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Привязки пользователей платформы к учётным записям во внешнем провайдере.
 */
@Repository
@RequiredArgsConstructor
class ExternalIdentityRepository {

    private final JdbcTemplate jdbc;

    Optional<Long> findUserId(String issuer, String subject) {
        List<Long> found = jdbc.queryForList(
                "SELECT user_id FROM external_identity WHERE issuer = ? AND subject = ?",
                Long.class,
                issuer,
                subject
        );

        return found.stream().findFirst();
    }

    /**
     * Идемпотентно: два одновременных первых входа одного человека создают одну привязку, а не падают.
     */
    void link(String issuer, String subject, Long userId) {
        jdbc.update(
                "INSERT INTO external_identity (issuer, subject, user_id) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
                issuer,
                subject,
                userId
        );
    }
}
