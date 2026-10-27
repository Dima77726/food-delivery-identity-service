package com.dima.fooddelivery.common.security;

import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.domain.UserRole;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * Выпуск access-токена. Единственное место во всей системе, где токены подписываются.
 *
 * <p>Проверкой подписи и срока занимается Spring Security на входе каждого сервиса — своего
 * парсера JWT в проекте нет и быть не должно. Самописный разбор токена это классическое место,
 * где забывают проверить алгоритм подписи и принимают {@code alg: none}.
 *
 * <p>В токен кладётся то, что нужно для авторизации и аудита: идентификатор в {@code sub},
 * роли в {@code roles} и e-mail. E-mail нужен журналу аудита в других сервисах: он фиксирует,
 * кто совершил действие, на момент действия, а ходить за этим в сервис пользователей на каждую
 * запись журнала — лишний сетевой вызов на пути каждого заказа. Телефона и имени в токене нет:
 * токен лежит у клиента и читается кем угодно, это подписанный, а не зашифрованный контейнер.
 *
 * <p>В заголовок кладётся {@code kid}: по нему проверяющий выбирает ключ из JWKS. Без него
 * при смене ключа проверяющим пришлось бы перебирать все ключи наугад.
 */
@Component
@RequiredArgsConstructor
public class JwtIssuer {

    public static final String ROLES_CLAIM = "roles";
    public static final String EMAIL_CLAIM = "email";
    public static final String API_KEY_CLAIM = "api_key_id";

    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;

    public IssuedToken issue(AppUser user) {
        return issue(user, null);
    }

    /**
     * Токен по ключу API партнёра: тот же владелец и те же роли, плюс claim {@value #API_KEY_CLAIM}.
     * Сервисы проверяют его как обычный — менять их не нужно, — а журналы и трассы видят, что
     * действие выполнила интеграция, а не человек в браузере.
     */
    public IssuedToken issueForApiKey(AppUser user, long apiKeyId) {
        return issue(user, apiKeyId);
    }

    private IssuedToken issue(AppUser user, Long apiKeyId) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(jwtProperties.accessTokenTtl());

        List<String> roles = user.getRoles().stream().map(UserRole::name).toList();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject(String.valueOf(user.getId()))
                .claim(ROLES_CLAIM, roles)
                .claim(EMAIL_CLAIM, user.getEmail())
                .claims(c -> {
                    if (apiKeyId != null) {
                        c.put(API_KEY_CLAIM, apiKeyId);
                    }
                })
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .keyId(jwtProperties.keyId())
                .build();

        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        return new IssuedToken(token, expiresAt, jwtProperties.accessTokenTtl().toSeconds());
    }

    public record IssuedToken(String token, Instant expiresAt, long expiresInSeconds) {
    }
}
