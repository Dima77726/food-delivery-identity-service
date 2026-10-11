package com.dima.fooddelivery.user.api;

import com.dima.fooddelivery.user.domain.UserRole;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Регистрация.
 *
 * <p>Роль ADMIN через этот запрос получить нельзя — за этим следит сервис. Иначе любой
 * желающий выдал бы себе администратора одним полем в JSON.
 */
public record RegisterUserRequest(
        @NotBlank(message = "email обязателен")
        @Email(message = "email должен быть корректным адресом")
        @Size(max = 255, message = "email не длиннее 255 символов")
        String email,

        @NotBlank(message = "пароль обязателен")
        @Size(min = 8, max = 100, message = "пароль от 8 до 100 символов")
        String password,

        @NotBlank(message = "имя обязательно")
        @Size(max = 255, message = "имя не длиннее 255 символов")
        String fullName,

        @Size(max = 50, message = "телефон не длиннее 50 символов")
        String phone,

        @NotNull(message = "роль обязательна")
        UserRole role
) {
}
