package com.dima.fooddelivery.user.service;

import com.dima.fooddelivery.common.security.JwtIssuer;
import com.dima.fooddelivery.user.api.AuthTokenResponse;
import com.dima.fooddelivery.user.api.LoginRequest;
import com.dima.fooddelivery.user.api.RegisterUserRequest;
import com.dima.fooddelivery.user.api.UserResponseMapper;
import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.persistence.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Регистрация и вход.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    /**
     * Хеш заведомо несуществующего пароля. Нужен, чтобы при неизвестном e-mail всё равно
     * выполнить проверку BCrypt: иначе ответ по несуществующему пользователю приходил бы
     * заметно быстрее, и по времени ответа можно было бы перебрать существующие адреса.
     */
    private static final String DUMMY_HASH =
            "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    private final AppUserRepository appUserRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtIssuer jwtIssuer;

    @Transactional
    public AuthTokenResponse register(RegisterUserRequest request) {
        AppUser user = userService.createUser(
                request.email(),
                request.password(),
                request.fullName(),
                request.phone(),
                request.role(),
                false
        );

        return issueToken(user);
    }

    @Transactional(readOnly = true)
    public AuthTokenResponse login(LoginRequest request) {
        AppUser user = appUserRepository.findByEmail(request.email()).orElse(null);

        String hashToCheck = user == null ? DUMMY_HASH : user.getPasswordHash();
        boolean passwordMatches = passwordEncoder.matches(request.password(), hashToCheck);

        if (user == null || !passwordMatches) {
            log.warn("Неудачная попытка входа: email={}", request.email());

            // Одно и то же сообщение для «нет такого пользователя» и «неверный пароль»:
            // различать их — значит подтверждать, какие адреса зарегистрированы.
            throw new BadCredentialsException("Неверный e-mail или пароль");
        }

        if (!user.isEnabled()) {
            log.warn("Попытка входа заблокированного пользователя: userId={}", user.getId());

            throw new DisabledException("Учётная запись заблокирована");
        }

        log.info("Успешный вход: userId={}", user.getId());

        return issueToken(user);
    }

    private AuthTokenResponse issueToken(AppUser user) {
        JwtIssuer.IssuedToken issued = jwtIssuer.issue(user);

        return new AuthTokenResponse(
                issued.token(),
                "Bearer",
                issued.expiresInSeconds(),
                UserResponseMapper.toResponse(user)
        );
    }
}
