package com.dima.fooddelivery.federation;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Вход через внешнего провайдера включается только флагом {@code app.oidc.enabled}: без него в сервисе нет ни
 * эндпоинта, ни клиента провайдера, и ему не нужна сеть до Keycloak.
 */
@Configuration
@EnableConfigurationProperties(OidcProperties.class)
@ConditionalOnProperty(name = "app.oidc.enabled", havingValue = "true")
class FederationConfig {

    /** Тесты подменяют проверку собственным бином, поэтому условие на отсутствие. */
    @Bean
    @ConditionalOnMissingBean
    OidcTokenVerifier oidcTokenVerifier(OidcProperties properties) {
        return OidcTokenVerifier.from(properties);
    }
}
