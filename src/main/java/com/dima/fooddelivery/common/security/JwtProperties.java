package com.dima.fooddelivery.common.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Настройки выпуска JWT.
 *
 * @param issuer         издатель — его сверяют все проверяющие сервисы
 * @param accessTokenTtl срок жизни access-токена
 * @param privateKey     закрытый RSA-ключ: PKCS#8 в DER, закодированный в Base64 одной строкой.
 *                       Одна строка, а не PEM, потому что многострочное значение в .env
 *                       и переменных окружения — источник тихих поломок при копировании
 * @param keyId          идентификатор ключа ({@code kid}). Проверяющие ищут по нему открытый
 *                       ключ в JWKS; при смене ключа новый получает новый kid, и оба живут
 *                       в JWKS, пока не истекут токены, подписанные старым
 */
@ConfigurationProperties(prefix = "app.security.jwt")
public record JwtProperties(
        String issuer,
        Duration accessTokenTtl,
        String privateKey,
        String keyId
) {
}
