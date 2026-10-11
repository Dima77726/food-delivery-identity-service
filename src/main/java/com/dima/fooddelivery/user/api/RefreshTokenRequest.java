package com.dima.fooddelivery.user.api;

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(
        @NotBlank(message = "refreshToken обязателен")
        String refreshToken
) {
}
