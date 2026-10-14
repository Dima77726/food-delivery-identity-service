package com.dima.fooddelivery.federation;

import com.dima.fooddelivery.common.exception.BusinessRuleViolationException;
import com.dima.fooddelivery.user.api.AuthTokenResponse;
import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.domain.UserRole;
import com.dima.fooddelivery.user.persistence.AppUserRepository;
import com.dima.fooddelivery.user.service.AuthService;
import com.dima.fooddelivery.user.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Вход через внешнего провайдера (Keycloak): токен провайдера обменивается на токен платформы.
 *
 * <p><b>Зачем обмен, а не прямая проверка токенов Keycloak во всех сервисах.</b> Владельцем пользователей,
 * ролей и прав на рестораны остаётся платформа: в её токене лежит собственный числовой идентификатор, на который
 * завязаны пути API и все сервисы. Провайдер отвечает за то, что он умеет лучше: как человека опознают
 * (форма входа, подтверждение почты, защита от перебора, при желании — второй фактор и соцсети). Сервисам
 * от этого ничего менять не пришлось.
 *
 * <p><b>Как находится пользователь:</b>
 * <ol>
 *   <li>по связи (издатель, subject) — основной путь, адрес в нём не участвует;</li>
 *   <li>иначе по подтверждённому адресу почты у существующего пользователя — и связь запоминается;</li>
 *   <li>иначе создаётся новый: с ролью из токена, но только из {@link OidcProperties#grantableRoles()}.</li>
 * </ol>
 *
 * <p><b>Роли платформа не синхронизирует.</b> Они берутся из токена один раз, при создании. Дальше их меняет только
 * платформа (админка): иначе человека с ролью, повышенной у провайдера, нельзя было бы понизить здесь, а любой сбой
 * или смена настроек у провайдера тихо раздавали бы права.
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "app.oidc.enabled", havingValue = "true")
public class FederatedLoginService {

    /** Порядок, в котором роль из токена становится основной ролью нового пользователя. */
    private static final List<UserRole> ROLE_PRIORITY = List.of(UserRole.CUSTOMER, UserRole.RESTAURANT_OWNER, UserRole.COURIER);

    private static final SecureRandom RANDOM = new SecureRandom();

    private final OidcTokenVerifier verifier;
    private final OidcProperties properties;
    private final ExternalIdentityRepository identities;
    private final AppUserRepository appUserRepository;
    private final UserService userService;
    private final AuthService authService;

    @Transactional
    public AuthTokenResponse exchange(String providerToken) {
        OidcTokenVerifier.VerifiedIdentity identity;

        try {
            identity = verifier.verify(providerToken);
        } catch (BadCredentialsException rejected) {
            log.warn("Вход через провайдера отклонён: {}", rejected.getMessage());

            throw rejected;
        }

        AppUser user = resolveUser(identity);

        if (!user.isEnabled()) {
            log.warn("Попытка входа через провайдера заблокированного пользователя: userId={}", user.getId());

            throw new DisabledException("Учётная запись заблокирована");
        }

        log.info("Успешный вход через провайдера: userId={}, issuer={}", user.getId(), identity.issuer());

        return authService.issueFor(user);
    }

    private AppUser resolveUser(OidcTokenVerifier.VerifiedIdentity identity) {
        Optional<AppUser> linked = identities.findUserId(identity.issuer(), identity.subject())
                .flatMap(appUserRepository::findById);

        if (linked.isPresent()) {
            return linked.get();
        }

        Optional<AppUser> sameEmail = appUserRepository.findByEmail(identity.email());

        if (sameEmail.isPresent()) {
            return linkExisting(sameEmail.get(), identity);
        }

        return createAndLink(identity);
    }

    private AppUser linkExisting(AppUser user, OidcTokenVerifier.VerifiedIdentity identity) {
        if (user.hasRole(UserRole.ADMIN) && !properties.linkAdminAccounts()) {
            log.warn("Отказ в привязке провайдера к учётной записи администратора: userId={}", user.getId());

            // Тот же ответ, что и на неверный токен: не подтверждаем, что такой адрес у администратора есть.
            throw new BadCredentialsException("Токен провайдера не принят");
        }

        identities.link(identity.issuer(), identity.subject(), user.getId());

        log.info("Учётная запись провайдера привязана к существующему пользователю: userId={}", user.getId());

        return user;
    }

    private AppUser createAndLink(OidcTokenVerifier.VerifiedIdentity identity) {
        List<UserRole> roles = rolesFor(identity);

        AppUser user;

        try {
            // Пароль случайный и никому не известен: войти по паролю в такую запись нельзя, только через провайдера.
            user = userService.createUser(identity.email(), randomPassword(), identity.name(), null, roles.get(0), false);
        } catch (BusinessRuleViolationException duplicate) {
            // Параллельный первый вход того же человека успел создать запись раньше: берём её.
            return appUserRepository.findByEmail(identity.email())
                    .map(existing -> linkExisting(existing, identity))
                    .orElseThrow(() -> duplicate);
        }

        roles.stream().skip(1).forEach(role -> userService.grantRole(user.getId(), role));
        identities.link(identity.issuer(), identity.subject(), user.getId());

        return user;
    }

    /** Роли из токена, допустимые к выдаче; без них — CUSTOMER. */
    private List<UserRole> rolesFor(OidcTokenVerifier.VerifiedIdentity identity) {
        List<UserRole> granted = ROLE_PRIORITY.stream()
                .filter(properties.grantableRoles()::contains)
                .filter(role -> identity.roles().contains(role.name()))
                .toList();

        return granted.isEmpty() ? List.of(UserRole.CUSTOMER) : granted;
    }

    private static String randomPassword() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
