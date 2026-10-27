package com.dima.fooddelivery.apikey;

import com.dima.fooddelivery.common.security.AccessDeniedForResourceException;
import com.dima.fooddelivery.common.security.CurrentUser;
import com.dima.fooddelivery.common.security.JwtIssuer;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * Ключи API партнёров. Выпускает и отзывает их владелец ресторана из своего кабинета; обмен
 * ключа на токен открыт — доступ даёт сам ключ.
 *
 * <p>Пути под {@code /api/v1/auth}: шлюз уже ведёт их в identity-service и считает по строгому
 * ведру ограничения частоты — перебор ключей так же бесполезен, как перебор паролей.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth/api-keys")
@Tag(name = "API keys", description = "Ключи API партнёров и их обмен на токен")
public class ApiKeyController {

    public static final String API_KEY_HEADER = "X-Api-Key";

    private final ApiKeyService apiKeyService;
    private final CurrentUser currentUser;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasRole('RESTAURANT_OWNER')")
    @SecurityRequirement(name = "bearer-jwt")
    @Operation(summary = "Выпустить ключ API (полный ключ показывается один раз)")
    public ApiKeyService.IssuedKey create(@Valid @RequestBody CreateApiKeyRequest request) {
        requireHumanSession();
        return apiKeyService.create(currentUser.requireId(), request.name());
    }

    @GetMapping
    @PreAuthorize("hasRole('RESTAURANT_OWNER')")
    @SecurityRequirement(name = "bearer-jwt")
    @Operation(summary = "Мои ключи API — без секретов")
    public List<ApiKeyResponse> list() {
        return apiKeyService.list(currentUser.requireId()).stream()
                .map(key -> new ApiKeyResponse(key.id(), key.name(), ApiKeyService.KEY_PREFIX + key.prefix(),
                        key.createdAt(), key.lastUsedAt(), key.revokedAt()))
                .toList();
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @PreAuthorize("hasRole('RESTAURANT_OWNER')")
    @SecurityRequirement(name = "bearer-jwt")
    @Operation(summary = "Отозвать ключ: следующий обмен на токен будет отклонён")
    public void revoke(@PathVariable Long id) {
        requireHumanSession();
        apiKeyService.revoke(currentUser.requireId(), id);
    }

    @PostMapping("/token")
    @Operation(summary = "Обменять ключ API (заголовок X-Api-Key) на access-токен")
    public ApiKeyTokenResponse token(@RequestHeader(name = API_KEY_HEADER, required = false) String apiKey) {
        JwtIssuer.IssuedToken issued = apiKeyService.exchange(apiKey);
        return new ApiKeyTokenResponse(issued.token(), "Bearer", issued.expiresInSeconds());
    }

    public record CreateApiKeyRequest(
            @NotBlank(message = "Назовите ключ — например, «Касса на Тверской»")
            @Size(max = 100, message = "Название не длиннее 100 символов")
            String name
    ) {
    }

    /** @param prefix открытая часть ключа: по ней ключ узнаётся в списке и в логах */
    public record ApiKeyResponse(
            long id,
            String name,
            String prefix,
            OffsetDateTime createdAt,
            OffsetDateTime lastUsedAt,
            OffsetDateTime revokedAt
    ) {
    }

    /** Без refresh-токена: у интеграции есть ключ, за новым токеном она просто приходит снова. */
    public record ApiKeyTokenResponse(String accessToken, String tokenType, long expiresInSeconds) {
    }

    /**
     * Управлять ключами можно только из сессии человека. Иначе утёкший ключ выпустил бы себе
     * замену, которая пережила бы его отзыв.
     */
    private static void requireHumanSession() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.getPrincipal() instanceof Jwt jwt
                && jwt.hasClaim(JwtIssuer.API_KEY_CLAIM)) {
            throw new AccessDeniedForResourceException("Ключами API управляют из кабинета, а не по ключу API");
        }
    }
}
