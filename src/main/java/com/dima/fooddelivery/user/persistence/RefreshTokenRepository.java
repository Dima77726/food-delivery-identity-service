package com.dima.fooddelivery.user.persistence;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

/**
 * Refresh-токены на {@link JdbcTemplate}, без Hibernate.
 *
 * <p>Сущность здесь не нужна: у токена нет поведения, а главная операция — обмен — должна быть
 * одним атомарным {@code UPDATE ... RETURNING}. Через персистентный контекст это было бы
 * «прочитать, проверить, записать», и два параллельных обмена одного токена прошли бы оба.
 */
@Repository
@RequiredArgsConstructor
public class RefreshTokenRepository {

    private final JdbcTemplate jdbcTemplate;

    public void insert(String tokenHash, Long userId, UUID familyId, Instant expiresAt) {
        jdbcTemplate.update("""
                        INSERT INTO refresh_token (token_hash, user_id, family_id, expires_at)
                        VALUES (?, ?, ?, ?)
                        """,
                tokenHash, userId, familyId, Timestamp.from(expiresAt));
    }

    /**
     * Помечает токен использованным, если он ещё действителен, и возвращает его владельца
     * и цепочку.
     *
     * <p>Проверка и запись — одно выражение: из двух одновременных обменов одного токена строку
     * обновит только первый, второй получит пустой результат и пойдёт по ветке повторного
     * предъявления.
     */
    public Optional<Consumed> consume(String tokenHash) {
        return jdbcTemplate.query("""
                                UPDATE refresh_token
                                SET used_at = CURRENT_TIMESTAMP
                                WHERE token_hash = ?
                                  AND used_at IS NULL
                                  AND revoked_at IS NULL
                                  AND expires_at > CURRENT_TIMESTAMP
                                RETURNING user_id, family_id
                                """,
                        (rs, rowNum) -> new Consumed(rs.getLong("user_id"), rs.getObject("family_id", UUID.class)),
                        tokenHash)
                .stream()
                .findFirst();
    }

    /** Состояние токена, который не удалось обменять: был ли он уже использован и в какой цепочке. */
    public Optional<Rejected> findRejected(String tokenHash) {
        return jdbcTemplate.query("""
                                SELECT user_id, family_id, used_at IS NOT NULL AS used
                                FROM refresh_token
                                WHERE token_hash = ?
                                """,
                        (rs, rowNum) -> new Rejected(
                                rs.getLong("user_id"),
                                rs.getObject("family_id", UUID.class),
                                rs.getBoolean("used")),
                        tokenHash)
                .stream()
                .findFirst();
    }

    public Optional<UUID> findFamily(String tokenHash) {
        return jdbcTemplate.query("SELECT family_id FROM refresh_token WHERE token_hash = ?",
                        (rs, rowNum) -> rs.getObject("family_id", UUID.class),
                        tokenHash)
                .stream()
                .findFirst();
    }

    public int revokeFamily(UUID familyId) {
        return jdbcTemplate.update("""
                        UPDATE refresh_token
                        SET revoked_at = CURRENT_TIMESTAMP
                        WHERE family_id = ? AND revoked_at IS NULL
                        """,
                familyId);
    }

    public int revokeAllOfUser(Long userId) {
        return jdbcTemplate.update("""
                        UPDATE refresh_token
                        SET revoked_at = CURRENT_TIMESTAMP
                        WHERE user_id = ? AND revoked_at IS NULL
                        """,
                userId);
    }

    /**
     * Удаляет истёкшие токены. Вместе с ними уходит и возможность заметить повторное
     * предъявление старого токена — но истёкший токен отклоняется и так.
     */
    public int deleteExpired() {
        return jdbcTemplate.update("DELETE FROM refresh_token WHERE expires_at < CURRENT_TIMESTAMP");
    }

    public record Consumed(Long userId, UUID familyId) {
    }

    public record Rejected(Long userId, UUID familyId, boolean used) {
    }
}
