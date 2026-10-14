package com.dima.fooddelivery.federation;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Проверяет токен внешнего провайдера и достаёт из него то, что нужно платформе.
 *
 * <p>Токену провайдера верить можно только после всех проверок, и ни одной из них нельзя пропустить:
 * <ul>
 *   <li><b>подпись</b> — только RS256, ключи берутся у провайдера по JWKS;</li>
 *   <li><b>издатель и срок действия</b> — токен другого realm или просроченный не годится;</li>
 *   <li><b>клиент ({@code azp})</b> — токен, выданный провайдером другому приложению, не для нас;</li>
 *   <li><b>подтверждённая почта</b> — привязка к пользователю платформы идёт по адресу, и непроверенный адрес
 *       позволил бы завести у провайдера запись с чужой почтой и войти под чужим именем.</li>
 * </ul>
 * Любая неудача — {@link BadCredentialsException}, то есть 401 без подробностей: причину отказа клиенту
 * знать незачем, она есть в журнале.
 */
public class OidcTokenVerifier {

    private static final int MAX_TOKEN_LENGTH = 8192;

    private final JwtDecoder decoder;

    /** Для тестов и для сборки из настроек: декодер уже знает, чьи ключи и какого издателя проверять. */
    public OidcTokenVerifier(JwtDecoder decoder) {
        this.decoder = decoder;
    }

    /** Боевая сборка: ключи по JWKS, издатель и клиенты из настроек. */
    public static OidcTokenVerifier from(OidcProperties properties) {
        if (properties.issuer() == null || properties.issuer().isBlank()
                || properties.jwkSetUri() == null || properties.jwkSetUri().isBlank()) {
            throw new IllegalStateException("app.oidc.enabled=true, но не заданы OIDC_ISSUER и OIDC_JWK_SET_URI");
        }

        if (properties.clientIds() == null || properties.clientIds().isEmpty()) {
            throw new IllegalStateException(
                    "app.oidc.enabled=true, но не задан ни один клиент (OIDC_CLIENT_IDS): без проверки клиента "
                            + "подошёл бы токен любого приложения этого realm"
            );
        }

        // Свой RestTemplate с таймаутами: загрузка ключей идёт в потоке запроса входа.
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(properties.jwkRefreshTimeout());
        requestFactory.setReadTimeout(properties.jwkRefreshTimeout());

        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(properties.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .restOperations(new RestTemplate(requestFactory))
                .build();

        decoder.setJwtValidator(validators(properties.issuer(), Set.copyOf(properties.clientIds())));

        return new OidcTokenVerifier(decoder);
    }

    /**
     * Правила проверки claims: издатель, срок действия и клиент. Вынесены отдельно, чтобы тесты проверяли
     * те же правила, что и боевая сборка, а не их копию.
     */
    static OAuth2TokenValidator<Jwt> validators(String issuer, Set<String> allowedClients) {
        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),
                clientValidator(allowedClients)
        );
    }

    public VerifiedIdentity verify(String token) {
        if (token == null || token.isBlank() || token.length() > MAX_TOKEN_LENGTH) {
            throw new BadCredentialsException("Токен провайдера не принят");
        }

        Jwt jwt;

        try {
            jwt = decoder.decode(token);
        } catch (JwtException exception) {
            throw new BadCredentialsException("Токен провайдера не принят", exception);
        }

        String email = jwt.getClaimAsString("email");

        if (!Boolean.TRUE.equals(jwt.getClaimAsBoolean("email_verified")) || email == null || email.isBlank()) {
            throw new BadCredentialsException("Почта в токене провайдера отсутствует или не подтверждена");
        }

        String subject = jwt.getSubject();

        if (subject == null || subject.isBlank() || jwt.getIssuer() == null) {
            throw new BadCredentialsException("В токене провайдера нет издателя или subject");
        }

        return new VerifiedIdentity(
                jwt.getIssuer().toString(),
                subject,
                email.trim(),
                displayName(jwt, email),
                realmRoles(jwt)
        );
    }

    private static OAuth2TokenValidator<Jwt> clientValidator(Set<String> allowedClients) {
        return jwt -> {
            String authorizedParty = jwt.getClaimAsString("azp");

            if (authorizedParty != null && allowedClients.contains(authorizedParty)) {
                return OAuth2TokenValidatorResult.success();
            }

            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Токен выдан другому клиенту", null)
            );
        };
    }

    private static String displayName(Jwt jwt, String email) {
        for (String claim : List.of("name", "preferred_username")) {
            String value = jwt.getClaimAsString(claim);

            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }

        return email.trim();
    }

    /** Роли realm лежат в {@code realm_access.roles}; всё, что не похоже на список строк, игнорируется. */
    private static Set<String> realmRoles(Jwt jwt) {
        Object realmAccess = jwt.getClaim("realm_access");

        if (!(realmAccess instanceof Map<?, ?> access) || !(access.get("roles") instanceof Collection<?> roles)) {
            return Set.of();
        }

        return roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .collect(Collectors.toUnmodifiableSet());
    }

    /**
     * Проверенные данные о человеке.
     *
     * @param issuer  издатель токена; вместе с {@code subject} однозначно определяет учётную запись у провайдера
     * @param subject постоянный идентификатор у провайдера
     * @param email   подтверждённая у провайдера почта
     * @param name    имя для нового пользователя
     * @param roles   роли realm; платформа сама решает, какие из них принять
     */
    public record VerifiedIdentity(String issuer, String subject, String email, String name, Set<String> roles) {
    }
}
