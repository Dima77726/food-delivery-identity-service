package com.dima.fooddelivery.federation;

import com.dima.fooddelivery.user.api.AuthTokenResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Обмен токена внешнего провайдера на токен платформы. Эндпоинта нет вовсе, пока
 * {@code app.oidc.enabled} не включён.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@ConditionalOnProperty(name = "app.oidc.enabled", havingValue = "true")
@Tag(name = "Auth", description = "Регистрация, вход, обмен токенов, выход и текущий пользователь")
public class FederationController {

    private final FederatedLoginService federatedLoginService;

    @PostMapping("/oidc")
    @Operation(summary = "Войти через внешнего провайдера (Keycloak): обменять его access-токен на токен платформы")
    public AuthTokenResponse exchange(@Valid @RequestBody OidcLoginRequest request) {
        return federatedLoginService.exchange(request.token());
    }

    /** Токен провайдера. Ограничение длины защищает от гигантских тел, которые разбирались бы впустую. */
    public record OidcLoginRequest(@NotBlank @Size(max = 8192) String token) {
    }
}
