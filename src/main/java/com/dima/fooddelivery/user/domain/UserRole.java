package com.dima.fooddelivery.user.domain;

/**
 * Роли платформы.
 *
 * <p>Spring Security ожидает authority с префиксом {@code ROLE_}, когда проверка написана как
 * {@code hasRole('CUSTOMER')}. Префикс добавляется здесь, в одном месте, а не рассыпан
 * по строковым литералам в конфигурации.
 */
public enum UserRole {

    CUSTOMER,
    RESTAURANT_OWNER,
    COURIER,
    ADMIN;

    public static final String ROLE_PREFIX = "ROLE_";

    public String authority() {
        return ROLE_PREFIX + name();
    }

    public static UserRole fromDbValue(String dbValue) {
        for (UserRole role : values()) {
            if (role.name().equals(dbValue)) {
                return role;
            }
        }

        throw new IllegalArgumentException("Неизвестная роль пользователя из базы данных: " + dbValue);
    }
}
