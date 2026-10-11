package com.dima.fooddelivery.user.api;

import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank(message = "email обязателен")
        String email,

        @NotBlank(message = "пароль обязателен")
        String password
) {
}
