package com.dima.fooddelivery.federation;

import com.dima.fooddelivery.user.domain.UserRole;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Вход через внешний OIDC-провайдер (Keycloak): {@code app.oidc.*}.
 *
 * @param enabled              включён ли обмен токена провайдера на токен платформы
 * @param issuer               издатель токенов в точности так, как он записан в claim {@code iss}: проверяется
 *                             строкой, поэтому адрес должен совпадать с тем, по которому провайдер виден клиентам
 * @param jwkSetUri            откуда брать открытые ключи провайдера. Отдельно от издателя: изнутри сети
 *                             Docker провайдер доступен по другому адресу, чем снаружи
 * @param clientIds            клиенты провайдера, чьи токены принимаются ({@code azp}). Токен любого другого
 *                             клиента того же realm отвергается: он выдан не для нашего приложения
 * @param grantableRoles       роли, которые можно получить из токена провайдера при создании пользователя.
 *                             ADMIN здесь быть не должно: права администратора выдаёт только сама платформа
 * @param linkAdminAccounts    разрешено ли привязывать вход через провайдера к существующей учётной записи
 *                             администратора. По умолчанию нет: за такую запись нельзя отдавать контроль
 *                             тому, кто лишь подтвердил почту на стороне провайдера
 * @param jwkRefreshTimeout    сколько ждать ответа провайдера при загрузке ключей
 */
@ConfigurationProperties(prefix = "app.oidc")
public record OidcProperties(
        @DefaultValue("false") boolean enabled,
        String issuer,
        String jwkSetUri,
        @DefaultValue List<String> clientIds,
        @DefaultValue({"CUSTOMER", "RESTAURANT_OWNER", "COURIER"}) Set<UserRole> grantableRoles,
        @DefaultValue("false") boolean linkAdminAccounts,
        @DefaultValue("5s") Duration jwkRefreshTimeout
) {
}
