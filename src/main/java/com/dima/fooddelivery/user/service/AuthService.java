package com.dima.fooddelivery.user.service;

import com.dima.fooddelivery.common.exception.InvalidRefreshTokenException;
import com.dima.fooddelivery.common.security.JwtIssuer;
import com.dima.fooddelivery.user.api.AuthTokenResponse;
import com.dima.fooddelivery.user.api.LoginRequest;
import com.dima.fooddelivery.user.api.RefreshTokenRequest;
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
 * Регистрация, вход, обмен refresh-токена и выход.
 *
 * <p>Вход выдаёт пару: короткий access-токен (JWT, проверяется любым сервисом без похода сюда)
 * и долгий refresh-токен (проверяется только здесь, по базе). Первый нельзя отозвать, зато он
 * живёт минуты; второй живёт неделями, зато отзывается мгновенно.
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
    private final RefreshTokenService refreshTokenService;

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

    @Transactional
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

    /**
     * Обмен refresh-токена на новую пару. Без транзакции здесь: она открывается внутри
     * {@link RefreshTokenService#rotate}, и исключение ниже бросается уже после её фиксации —
     * отзыв цепочки при повторном предъявлении не откатывается.
     */
    public AuthTokenResponse refresh(RefreshTokenRequest request) {
        return switch (refreshTokenService.rotate(request.refreshToken())) {
            case RefreshTokenService.Rotation.Rotated rotated ->
                    toResponse(rotated.user(), rotated.refreshToken());
            case RefreshTokenService.Rotation.Disabled disabled ->
                    throw new DisabledException("Учётная запись заблокирована");
            case RefreshTokenService.Rotation.Invalid invalid ->
                    throw new InvalidRefreshTokenException();
        };
    }

    public void logout(RefreshTokenRequest request) {
        refreshTokenService.revoke(request.refreshToken());
    }

    private AuthTokenResponse issueToken(AppUser user) {
        return toResponse(user, refreshTokenService.issue(user.getId()));
    }

    private AuthTokenResponse toResponse(AppUser user, RefreshTokenService.IssuedRefreshToken refreshToken) {
        JwtIssuer.IssuedToken issued = jwtIssuer.issue(user);

        return new AuthTokenResponse(
                issued.token(),
                "Bearer",
                issued.expiresInSeconds(),
                refreshToken.token(),
                refreshToken.expiresInSeconds(),
                UserResponseMapper.toResponse(user)
        );
    }
}
