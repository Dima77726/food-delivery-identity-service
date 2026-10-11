package com.dima.fooddelivery.user.service;

import com.dima.fooddelivery.common.security.JwtProperties;
import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.persistence.AppUserRepository;
import com.dima.fooddelivery.user.persistence.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

/**
 * Выпуск, обмен и отзыв refresh-токенов.
 *
 * <p>Токен — непрозрачная случайная строка, а не JWT. Его проверяет только этот сервис и только
 * по базе: смысл refresh-токена в том, что его можно отозвать, а подпись без похода в базу
 * отзыва не видит.
 *
 * <p>Обмен одноразовый (ротация): каждый токен меняется на новый ровно один раз. Если старый
 * предъявили повторно, значит, копий две, и какая из них у владельца — неизвестно. Поэтому
 * отзывается вся цепочка: и вор, и владелец входят заново, но вор — уже без пароля не войдёт.
 *
 * <p>Исходы обмена возвращаются значением, а не исключением. Отзыв цепочки при повторном
 * предъявлении обязан сохраниться, а исключение из {@code @Transactional}-метода откатило бы
 * его вместе со всем остальным.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final int TOKEN_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    private final RefreshTokenRepository refreshTokenRepository;
    private final AppUserRepository appUserRepository;
    private final JwtProperties jwtProperties;

    /** Новый токен в новой цепочке — при входе и регистрации. */
    @Transactional
    public IssuedRefreshToken issue(Long userId) {
        return issueInFamily(userId, UUID.randomUUID());
    }

    @Transactional
    public Rotation rotate(String rawToken) {
        String tokenHash = hash(rawToken);

        RefreshTokenRepository.Consumed consumed = refreshTokenRepository.consume(tokenHash).orElse(null);

        if (consumed == null) {
            return rejected(tokenHash);
        }

        AppUser user = appUserRepository.findById(consumed.userId()).orElse(null);

        if (user == null || !user.isEnabled()) {
            refreshTokenRepository.revokeFamily(consumed.familyId());
            log.warn("Обмен refresh-токена заблокированного пользователя: userId={}", consumed.userId());

            return new Rotation.Disabled();
        }

        return new Rotation.Rotated(user, issueInFamily(user.getId(), consumed.familyId()));
    }

    /**
     * Выход: отзывает цепочку, к которой принадлежит токен. Остальные устройства пользователя
     * остаются в системе — у каждого своя цепочка. Неизвестный токен — не ошибка: выйти
     * из несуществующей сессии значит уже быть вне её.
     */
    @Transactional
    public void revoke(String rawToken) {
        refreshTokenRepository.findFamily(hash(rawToken)).ifPresent(familyId -> {
            refreshTokenRepository.revokeFamily(familyId);
            log.info("Сессия завершена: familyId={}", familyId);
        });
    }

    /** Все сессии пользователя — при блокировке. */
    @Transactional
    public void revokeAll(Long userId) {
        int revoked = refreshTokenRepository.revokeAllOfUser(userId);

        log.info("Отозваны refresh-токены пользователя: userId={}, count={}", userId, revoked);
    }

    @Transactional
    public int deleteExpired() {
        return refreshTokenRepository.deleteExpired();
    }

    private Rotation rejected(String tokenHash) {
        RefreshTokenRepository.Rejected rejected = refreshTokenRepository.findRejected(tokenHash).orElse(null);

        if (rejected != null && rejected.used()) {
            int revoked = refreshTokenRepository.revokeFamily(rejected.familyId());
            log.warn("Повторное предъявление refresh-токена, цепочка отозвана: userId={}, familyId={}, revoked={}",
                    rejected.userId(), rejected.familyId(), revoked);
        }

        return new Rotation.Invalid();
    }

    private IssuedRefreshToken issueInFamily(Long userId, UUID familyId) {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);

        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        Instant expiresAt = Instant.now().plus(jwtProperties.refreshTokenTtl());

        refreshTokenRepository.insert(hash(rawToken), userId, familyId, expiresAt);

        return new IssuedRefreshToken(rawToken, jwtProperties.refreshTokenTtl().toSeconds());
    }

    private static String hash(String rawToken) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(rawToken.getBytes(StandardCharsets.UTF_8));

            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 обязан быть в любой JVM по спецификации Java SE.
            throw new IllegalStateException(e);
        }
    }

    public record IssuedRefreshToken(String token, long expiresInSeconds) {
    }

    public sealed interface Rotation {

        record Rotated(AppUser user, IssuedRefreshToken refreshToken) implements Rotation {
        }

        /** Токен неизвестен, истёк, отозван или уже использован. Клиенту причина не сообщается. */
        record Invalid() implements Rotation {
        }

        record Disabled() implements Rotation {
        }
    }
}
