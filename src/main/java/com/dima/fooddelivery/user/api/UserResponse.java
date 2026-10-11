package com.dima.fooddelivery.user.api;

import com.dima.fooddelivery.user.domain.UserRole;

import java.time.OffsetDateTime;
import java.util.Set;

/**
 * Пользователь в ответе API. Хеша пароля здесь нет и быть не должно — это единственная
 * причина, по которой доменный AppUser не отдаётся наружу напрямую.
 */
public record UserResponse(
        Long id,
        String email,
        String fullName,
        String phone,
        boolean enabled,
        Set<UserRole> roles,
        OffsetDateTime createdAt
) {
}
