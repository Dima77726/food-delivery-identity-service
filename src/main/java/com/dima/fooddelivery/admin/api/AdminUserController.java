package com.dima.fooddelivery.admin.api;

import com.dima.fooddelivery.admin.audit.AdminAuditLog;
import com.dima.fooddelivery.user.api.UserResponse;
import com.dima.fooddelivery.user.api.UserResponseMapper;
import com.dima.fooddelivery.user.domain.UserRole;
import com.dima.fooddelivery.user.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Positive;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Администрирование пользователей: роли, блокировка, управляющие ресторанов.
 *
 * <p>Переехало из монолита вместе с пользователями. Журнал аудита остался в монолите и читается
 * там же, по {@code /api/v1/admin/audit}; действия этого контроллера пишутся в собственный
 * журнал сервиса — см. {@link AdminAuditLog}.
 *
 * <p>Путь {@code /api/v1/admin/**} закрыт ролью ADMIN ещё в {@code SecurityConfig} — на уровне
 * фильтра. Дублирующий {@code @PreAuthorize} на классе стоит намеренно: если кто-то однажды
 * перепишет цепочку фильтров и забудет про этот префикс, вторая проверка не даст админке
 * открыться всем подряд.
 */
@Slf4j
@Validated
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/admin")
@Tag(name = "Admin", description = "Администрирование пользователей")
@SecurityRequirement(name = "bearer-jwt")
@PreAuthorize("hasRole('ADMIN')")
public class AdminUserController {

    private final UserService userService;
    private final AdminAuditLog auditLog;

    @GetMapping("/users")
    @Operation(summary = "Все пользователи платформы")
    public List<UserResponse> getUsers() {
        return UserResponseMapper.toResponses(userService.getAllUsers());
    }

    @PostMapping("/users/{userId}/roles/{role}")
    @Operation(summary = "Выдать пользователю роль")
    public UserResponse grantRole(
            @Positive @PathVariable Long userId,
            @PathVariable UserRole role
    ) {
        log.info("Выдача роли: userId={}, role={}", userId, role);

        UserResponse response = UserResponseMapper.toResponse(userService.grantRole(userId, role));

        auditLog.record("GRANT_ROLE", "USER", String.valueOf(userId), "Роль: " + role);

        return response;
    }

    @PostMapping("/users/{userId}/enable")
    @Operation(summary = "Разблокировать пользователя")
    public UserResponse enableUser(@Positive @PathVariable Long userId) {
        UserResponse response = UserResponseMapper.toResponse(userService.setEnabled(userId, true));

        auditLog.record("ENABLE_USER", "USER", String.valueOf(userId), null);

        return response;
    }

    @PostMapping("/users/{userId}/disable")
    @Operation(summary = "Заблокировать пользователя")
    public UserResponse disableUser(@Positive @PathVariable Long userId) {
        UserResponse response = UserResponseMapper.toResponse(userService.setEnabled(userId, false));

        auditLog.record("DISABLE_USER", "USER", String.valueOf(userId), null);

        return response;
    }

    @PostMapping("/users/{userId}/restaurants/{restaurantId}")
    @Operation(summary = "Назначить пользователя управляющим рестораном")
    public UserResponse assignRestaurantManager(
            @Positive @PathVariable Long userId,
            @Positive @PathVariable Long restaurantId
    ) {
        userService.assignRestaurantManager(userId, restaurantId);

        auditLog.record(
                "ASSIGN_RESTAURANT_MANAGER",
                "RESTAURANT",
                String.valueOf(restaurantId),
                "Управляющий: " + userId
        );

        return UserResponseMapper.toResponse(userService.requireUser(userId));
    }
}
