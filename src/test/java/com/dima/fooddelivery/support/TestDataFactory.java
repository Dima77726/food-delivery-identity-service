package com.dima.fooddelivery.support;

import com.dima.fooddelivery.user.domain.UserRole;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Собирает состояние базы сервиса пользователей для интеграционных тестов.
 *
 * <p>Данные вставляются напрямую через SQL, а не через сервисы: подготовка данных не должна
 * быть ещё одним тестируемым кодом.
 */
public class TestDataFactory {

    /**
     * Уникальные суффиксы для e-mail: у пользователей уникальный индекс по адресу, а откат
     * транзакции не сбрасывает последовательности — поэтому счётчик, а не константа.
     */
    private static final AtomicLong SEQUENCE = new AtomicLong(System.nanoTime());

    /** BCrypt-хеш строки "password123". */
    public static final String KNOWN_PASSWORD = "password123";
    private static final String KNOWN_PASSWORD_HASH =
            "$2a$10$3euPcmQFCiblsZeEu5s7p.9OVHgeHWFwaAHubD8Wypx0GKF/hi5Ne";

    private final JdbcTemplate jdbcTemplate;

    public TestDataFactory(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public long uniqueSuffix() {
        return SEQUENCE.incrementAndGet();
    }

    /**
     * Пользователь с ролями. Пароль кладётся заранее посчитанным BCrypt-хешом строки
     * {@code "password123"} — считать хеш на каждый вызов дорого: BCrypt намеренно медленный,
     * и на сотне тестов это заметно.
     */
    public Long insertUser(String emailPrefix, UserRole... roles) {
        Long userId = jdbcTemplate.queryForObject(
                """
                        INSERT INTO app_user (email, password_hash, full_name, phone)
                        VALUES (?, ?, ?, ?)
                        RETURNING id
                        """,
                Long.class,
                emailPrefix + "-" + uniqueSuffix() + "@example.test",
                KNOWN_PASSWORD_HASH,
                "Test User",
                "+70000000000"
        );

        for (UserRole role : roles) {
            jdbcTemplate.update(
                    "INSERT INTO app_user_role (user_id, role) VALUES (?, ?)",
                    userId,
                    role.name()
            );
        }

        return userId;
    }

    public Long insertCustomer() {
        return insertUser("customer", UserRole.CUSTOMER);
    }

    public Long insertCourier() {
        return insertUser("courier", UserRole.COURIER);
    }
}
