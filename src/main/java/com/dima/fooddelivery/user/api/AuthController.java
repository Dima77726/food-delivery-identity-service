package com.dima.fooddelivery.user.api;

import com.dima.fooddelivery.common.security.CurrentUser;
import com.dima.fooddelivery.user.service.AuthService;
import com.dima.fooddelivery.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
@Tag(name = "Auth", description = "Регистрация, вход и текущий пользователь")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final CurrentUser currentUser;

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Зарегистрировать пользователя и сразу получить токен")
    public AuthTokenResponse register(@Valid @RequestBody RegisterUserRequest request) {
        log.info("Запрос на регистрацию: email={}, role={}", request.email(), request.role());

        return authService.register(request);
    }

    @PostMapping("/login")
    @Operation(summary = "Войти и получить access-токен")
    public AuthTokenResponse login(@Valid @RequestBody LoginRequest request) {
        log.info("Запрос на вход: email={}", request.email());

        return authService.login(request);
    }

    /**
     * Кто я. Единственный способ для клиента узнать свой {@code userId}, который дальше
     * подставляется в пути вида {@code /api/v1/customers/{customerId}/orders}.
     */
    @GetMapping("/me")
    @Operation(summary = "Текущий пользователь по токену")
    public UserResponse me() {
        return UserResponseMapper.toResponse(userService.requireUser(currentUser.requireId()));
    }
}
