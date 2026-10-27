package com.dima.fooddelivery.apikey;

import com.dima.fooddelivery.common.exception.BusinessRuleViolationException;
import com.dima.fooddelivery.common.exception.ResourceNotFoundException;
import com.dima.fooddelivery.common.security.JwtIssuer;
import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.persistence.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Ключи API партнёров: выпуск, список, отзыв и обмен на токен платформы.
 *
 * <p><b>Формат:</b> {@code fdp_<префикс>_<секрет>}. Префикс (8 символов) открыт: по нему ключ
 * ищется в базе и узнаётся в списке. Секрет (32 символа, ~190 бит) показывается один раз при
 * выпуске; в базе — только его SHA-256.
 *
 * <p><b>Почему SHA-256, а не bcrypt, как у паролей.</b> Медленный хеш нужен паролям, потому что
 * их мало и их перебирают по словарю. Секрет ключа — 190 случайных бит: перебор невозможен при
 * любой скорости хеша, а быстрый хеш не тормозит каждый обмен.
 *
 * <p><b>Почему обмен на токен, а не ключ в каждом запросе.</b> Сервисы умеют проверять только
 * JWT, и проверяют без похода в базу. Ключ в каждом запросе заставил бы каждый сервис спрашивать
 * identity-service. Обмен — та же схема, что client credentials в OAuth 2: долгий секрет живёт у
 * партнёра, по сети ходит короткий токен. Отзыв ключа срабатывает на следующем обмене, то есть
 * не позже чем через время жизни токена (15 минут).
 *
 * <p>Ключ действует от имени владельца — с его ролями и его ресторанами. Ограничение ключа
 * отдельными ресторанами и действиями (scopes) — следующий шаг: для него сервисам пришлось бы
 * читать новые claims токена.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ApiKeyService {

    static final String KEY_PREFIX = "fdp_";
    static final int MAX_ACTIVE_KEYS = 10;

    private static final Pattern KEY_FORMAT = Pattern.compile("^fdp_([a-z0-9]{8})_([A-Za-z0-9]{32})$");
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static final String PREFIX_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();

    private final ApiKeyRepository repository;
    private final AppUserRepository userRepository;
    private final JwtIssuer jwtIssuer;

    @Transactional
    public IssuedKey create(Long userId, String name) {
        if (repository.countActiveByUser(userId) >= MAX_ACTIVE_KEYS) {
            throw new BusinessRuleViolationException("Не больше " + MAX_ACTIVE_KEYS + " действующих ключей: отзовите ненужные");
        }

        String prefix = random(PREFIX_ALPHABET, 8);
        String secret = random(ALPHABET, 32);
        long id = repository.insert(userId, name.strip(), prefix, sha256(secret));

        log.info("Выпущен ключ API: id={}, userId={}, prefix={}", id, userId, prefix);

        return new IssuedKey(id, name.strip(), prefix, KEY_PREFIX + prefix + "_" + secret);
    }

    @Transactional(readOnly = true)
    public List<ApiKeyRepository.StoredKey> list(Long userId) {
        return repository.findByUser(userId);
    }

    @Transactional
    public void revoke(Long userId, Long keyId) {
        if (!repository.revoke(keyId, userId)) {
            throw new ResourceNotFoundException("Действующий ключ с id=" + keyId + " не найден");
        }
        log.info("Ключ API отозван: id={}, userId={}", keyId, userId);
    }

    /**
     * Ключ в обмен на access-токен владельца.
     *
     * <p>Все отказы — одно и то же «неверный ключ»: различать «нет такого префикса», «не тот
     * секрет» и «отозван» — значит подсказывать, какие префиксы существуют.
     */
    @Transactional
    public JwtIssuer.IssuedToken exchange(String apiKey) {
        var matcher = apiKey == null ? null : KEY_FORMAT.matcher(apiKey.strip());
        if (matcher == null || !matcher.matches()) {
            throw new BadCredentialsException("Неверный ключ API");
        }

        ApiKeyRepository.StoredKey key = repository.findByPrefix(matcher.group(1))
                .filter(ApiKeyRepository.StoredKey::active)
                .filter(stored -> MessageDigest.isEqual(
                        stored.secretHash().getBytes(StandardCharsets.US_ASCII),
                        sha256(matcher.group(2)).getBytes(StandardCharsets.US_ASCII)))
                .orElseThrow(() -> {
                    log.warn("Отклонён ключ API с префиксом {}", matcher.group(1));
                    return new BadCredentialsException("Неверный ключ API");
                });

        AppUser user = userRepository.findById(key.userId())
                .orElseThrow(() -> new BadCredentialsException("Неверный ключ API"));
        if (!user.isEnabled()) {
            throw new DisabledException("Учётная запись заблокирована");
        }

        repository.touch(key.id());

        return jwtIssuer.issueForApiKey(user, key.id());
    }

    static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static String random(String alphabet, int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        }
        return builder.toString();
    }

    /** @param key полный ключ — показывается один раз, восстановить его потом нельзя */
    public record IssuedKey(long id, String name, String prefix, String key) {
    }
}
