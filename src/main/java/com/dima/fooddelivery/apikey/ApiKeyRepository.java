package com.dima.fooddelivery.apikey;

import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
class ApiKeyRepository {

    private static final RowMapper<StoredKey> KEY = (rs, rowNum) -> new StoredKey(
            rs.getLong("id"),
            rs.getLong("user_id"),
            rs.getString("name"),
            rs.getString("prefix"),
            rs.getString("secret_hash"),
            rs.getObject("created_at", OffsetDateTime.class),
            rs.getObject("last_used_at", OffsetDateTime.class),
            rs.getObject("revoked_at", OffsetDateTime.class)
    );

    private static final String SELECT = """
            SELECT id, user_id, name, prefix, secret_hash, created_at, last_used_at, revoked_at
            FROM partner_api_key
            """;

    private final JdbcTemplate jdbc;

    long insert(Long userId, String name, String prefix, String secretHash) {
        return jdbc.queryForObject(
                "INSERT INTO partner_api_key (user_id, name, prefix, secret_hash) VALUES (?, ?, ?, ?) RETURNING id",
                Long.class, userId, name, prefix, secretHash);
    }

    Optional<StoredKey> findByPrefix(String prefix) {
        return jdbc.query(SELECT + " WHERE prefix = ?", KEY, prefix).stream().findFirst();
    }

    List<StoredKey> findByUser(Long userId) {
        return jdbc.query(SELECT + " WHERE user_id = ? ORDER BY id DESC", KEY, userId);
    }

    long countActiveByUser(Long userId) {
        return jdbc.queryForObject(
                "SELECT COUNT(*) FROM partner_api_key WHERE user_id = ? AND revoked_at IS NULL", Long.class, userId);
    }

    /** Отзыв — отметка, а не удаление: в журнале остаётся, какой ключ что делал. */
    boolean revoke(Long id, Long userId) {
        return jdbc.update(
                "UPDATE partner_api_key SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
                id, userId) == 1;
    }

    /**
     * Не чаще раза в минуту: отметка нужна человеку («ключ жив?»), а запись на каждый обмен
     * превратила бы чтение в запись под нагрузкой.
     */
    void touch(Long id) {
        jdbc.update("""
                UPDATE partner_api_key SET last_used_at = CURRENT_TIMESTAMP
                WHERE id = ? AND (last_used_at IS NULL OR last_used_at < CURRENT_TIMESTAMP - INTERVAL '1 minute')
                """, id);
    }

    record StoredKey(
            long id,
            long userId,
            String name,
            String prefix,
            String secretHash,
            OffsetDateTime createdAt,
            OffsetDateTime lastUsedAt,
            OffsetDateTime revokedAt
    ) {
        boolean active() {
            return revokedAt == null;
        }
    }
}
