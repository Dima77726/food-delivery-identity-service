package com.dima.fooddelivery.user.service;

import com.dima.fooddelivery.common.exception.BusinessRuleViolationException;
import com.dima.fooddelivery.common.exception.ResourceNotFoundException;
import com.dima.fooddelivery.common.persistence.DataAccessErrors;
import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.domain.UserRole;
import com.dima.fooddelivery.user.persistence.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Модуль User: создание пользователей, роли, привязка управляющих к ресторанам.
 *
 * <p>Работает поверх Hibernate, но без Spring Data — репозиторий написан руками, см.
 * {@link AppUserRepository}. Изменения здесь, как и в остальных JPA-модулях, идут грязной
 * проверкой: вызов сеттера, а не UPDATE.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final AppUserRepository appUserRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Создаёт пользователя с одной ролью.
     *
     * @param allowPrivilegedRole разрешено ли выдать ADMIN; true только для вызова из админки
     */
    @Transactional
    public AppUser createUser(
            String email,
            String rawPassword,
            String fullName,
            String phone,
            UserRole role,
            boolean allowPrivilegedRole
    ) {
        if (role == UserRole.ADMIN && !allowPrivilegedRole) {
            log.warn("Попытка самостоятельно зарегистрироваться администратором: email={}", email);

            throw new BusinessRuleViolationException("Роль ADMIN не может быть получена при регистрации");
        }

        AppUser user = new AppUser(
                email.trim(),
                passwordEncoder.encode(rawPassword),
                fullName.trim(),
                phone
        );

        user.grantRole(role);

        try {
            appUserRepository.save(user);

            // Сброс обязателен: без него нарушение уникальности всплыло бы только при коммите,
            // за пределами этого try, и пользователь получил бы 500 вместо понятного ответа.
            appUserRepository.flush();
        } catch (DataIntegrityViolationException exception) {
            if (!DataAccessErrors.isUniqueViolation(exception)) {
                throw exception;
            }

            // Уникальность e-mail проверяет база: предварительный SELECT не спасал бы
            // от двух одновременных регистраций с одним адресом.
            log.warn("Регистрация с уже занятым e-mail: email={}", email);

            throw new BusinessRuleViolationException("Пользователь с e-mail " + email + " уже зарегистрирован");
        }

        log.info("Зарегистрирован пользователь: userId={}, role={}", user.getId(), role);

        return user;
    }

    @Transactional(readOnly = true)
    public AppUser requireUser(Long userId) {
        return appUserRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("Пользователь с id=" + userId + " не найден"));
    }

    @Transactional(readOnly = true)
    public List<AppUser> getAllUsers() {
        return appUserRepository.findAll();
    }

    @Transactional
    public AppUser grantRole(Long userId, UserRole role) {
        AppUser user = requireUser(userId);

        user.grantRole(role);
        appUserRepository.flush();

        log.info("Пользователю выдана роль: userId={}, role={}", userId, role);

        return user;
    }

    @Transactional
    public AppUser setEnabled(Long userId, boolean enabled) {
        AppUser user = requireUser(userId);

        user.setEnabled(enabled);
        appUserRepository.flush();

        log.info("Изменён доступ пользователя: userId={}, enabled={}", userId, enabled);

        return user;
    }

    /**
     * Привязывает пользователя к ресторану как управляющего.
     *
     * <p>Роль RESTAURANT_OWNER выдаётся здесь же: управлять рестораном, не имея роли,
     * бессмысленно, а забыть выдать её отдельным вызовом — легко.
     */
    @Transactional
    public void assignRestaurantManager(Long userId, Long restaurantId) {
        AppUser user = requireUser(userId);

        user.grantRole(UserRole.RESTAURANT_OWNER);
        user.addManagedRestaurant(restaurantId);
        appUserRepository.flush();

        log.info("Пользователь назначен управляющим рестораном: userId={}, restaurantId={}", userId, restaurantId);
    }

    /**
     * Управляет ли пользователь рестораном. Ответ для каталога — он спрашивает по gRPC перед
     * каждой операцией управления рестораном и меню.
     */
    @Transactional(readOnly = true)
    public boolean managesRestaurant(Long userId, Long restaurantId) {
        return appUserRepository.managesRestaurant(userId, restaurantId);
    }

    @Transactional(readOnly = true)
    public List<Long> getManagedRestaurantIds(Long userId) {
        return appUserRepository.findManagedRestaurantIds(userId);
    }
}
