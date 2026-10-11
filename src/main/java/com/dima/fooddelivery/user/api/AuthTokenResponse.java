package com.dima.fooddelivery.user.api;

public record AuthTokenResponse(
        String accessToken,
        String tokenType,
        long expiresInSeconds,
        String refreshToken,
        long refreshExpiresInSeconds,
        UserResponse user
) {
}
