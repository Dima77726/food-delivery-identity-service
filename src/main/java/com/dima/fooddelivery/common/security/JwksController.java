package com.dima.fooddelivery.common.security;

import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/**
 * Открытые ключи для проверки токенов — JWKS.
 *
 * <p>Путь {@code /.well-known/jwks.json} — общепринятый: клиенты OAuth2 и Spring Security
 * ищут ключи именно там. Остальные сервисы скачивают JWKS сами, кэшируют и перечитывают,
 * когда встречают незнакомый {@code kid}, — так смена ключа не требует их перезапуска.
 *
 * <p>Открыт без аутентификации: это открытые ключи, их смысл — быть доступными.
 * Через шлюз наружу путь не публикуется — сервисы ходят за ним напрямую, по внутренней сети.
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    /** Короткий кэш: снижает нагрузку, но не мешает быстро разнести новый ключ. */
    private static final Duration CACHE_TTL = Duration.ofMinutes(5);

    private final JwtKeys jwtKeys;

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(CACHE_TTL).cachePublic())
                .body(jwtKeys.publicJwkSet().toJSONObject());
    }
}
