package com.dima.fooddelivery.common.security;

import com.dima.fooddelivery.common.web.UserIdMdcFilter;
import com.dima.fooddelivery.user.domain.UserRole;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.autoconfigure.actuate.web.servlet.EndpointRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Безопасность сервиса пользователей.
 *
 * <p>Сервис и выпускает токены, и сам их принимает — на {@code /auth/me} и в админке.
 * Свои токены он проверяет тем же открытым ключом, что публикует в JWKS, но локально,
 * без похода по сети к самому себе.
 *
 * <p>Сессий нет: {@code STATELESS}. Отсюда и выключенный CSRF — cookie для аутентификации
 * не используются.
 */
@Configuration
@EnableMethodSecurity
@EnableConfigurationProperties(JwtProperties.class)
@RequiredArgsConstructor
public class SecurityConfig {

    private static final String[] PUBLIC_PATHS = {
            // Регистрация и вход обязаны быть открыты, иначе войти невозможно.
            "/api/v1/auth/register",
            "/api/v1/auth/login",
            // Обмен и выход приходят как раз тогда, когда access-токен уже истёк: доступ к ним
            // даёт сам refresh-токен в теле запроса.
            "/api/v1/auth/refresh",
            "/api/v1/auth/logout",
            // Открытые ключи — их смысл в том, чтобы быть доступными.
            "/.well-known/jwks.json",
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/swagger-ui.html"
    };

    private final JwtKeys jwtKeys;
    private final JwtProperties jwtProperties;
    private final CurrentUser currentUser;

    /** Actuator на отдельном порту, наружу не публикуется — защита сетевая. */
    @Bean
    @Order(1)
    SecurityFilterChain actuatorFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher(EndpointRequest.toAnyEndpoint())
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(PUBLIC_PATHS).permitAll()
                        .requestMatchers("/api/v1/admin/**").hasRole(UserRole.ADMIN.name())
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .addFilterAfter(new UserIdMdcFilter(currentUser), BearerTokenAuthenticationFilter.class);

        return http.build();
    }

    /**
     * BCrypt, а не SHA/MD5: он намеренно медленный и солит пароль сам. Быстрый хеш здесь —
     * ошибка, потому что скорость играет на стороне того, кто перебирает.
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwtKeys.signingKey())));
    }

    @Bean
    JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(jwtKeys.publicKey()).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(jwtProperties.issuer()));

        return decoder;
    }

    /** Без этого конвертер искал бы claim {@code scope}, и {@code hasRole} молча отказывал бы всем. */
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName(JwtIssuer.ROLES_CLAIM);
        authoritiesConverter.setAuthorityPrefix(UserRole.ROLE_PREFIX);

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);

        return converter;
    }
}
