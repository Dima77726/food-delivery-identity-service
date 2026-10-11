package com.dima.fooddelivery.user.domain;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.OffsetDateTime;
import java.util.Collections;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Пользователь платформы. Сущность Hibernate.
 *
 * <p>Модуль намеренно устроен иначе, чем {@code restaurant} и {@code menu}: Spring Data здесь
 * нет вовсе. Репозиторий написан руками поверх {@code EntityManager} — см.
 * {@code AppUserRepository}. Смысл в том, чтобы было видно, что Spring Data не является
 * обязательной частью JPA: она лишь избавляет от написания того же самого кода.
 *
 * <p>{@code passwordHash} лежит в доменном типе, но наружу через API не выходит: за этим следит
 * маппер в пакете {@code api}, который просто не переносит это поле в DTO. Отдельного типа
 * «пользователь без пароля» здесь нет намеренно — лишняя сущность ради одного поля.
 */
@Entity
@Table(name = "app_user")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class AppUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "full_name", nullable = false)
    private String fullName;

    @Column(length = 50)
    private String phone;

    @Setter
    @Column(name = "is_enabled", nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    /**
     * Роли пользователя — {@code @ElementCollection}, а не связь с сущностью.
     *
     * <p>Разница принципиальная. {@code @OneToMany} потребовал бы отдельного класса-сущности
     * с собственным идентификатором и жизненным циклом. Но у строки в {@code app_user_role}
     * нет ни того ни другого: там только внешний ключ и значение, первичный ключ составной,
     * а сама по себе, вне пользователя, такая строка не значит ничего.
     * {@code @ElementCollection} описывает ровно это — коллекцию значений, принадлежащих
     * владельцу. Hibernate сам поддерживает её содержимое: добавленный элемент становится
     * INSERT, убранный — DELETE.
     *
     * <p>{@code @Enumerated(STRING)} обязателен. По умолчанию JPA хранит enum порядковым
     * номером, и тогда любая вставка новой роли в середину перечисления молча переименовала бы
     * роли у всех существующих пользователей. В колонке лежит VARCHAR, и там же стоит
     * constraint {@code chk_app_user_role} с перечнем допустимых строк.
     *
     * <p>Загрузка ленивая — так по умолчанию, и менять это не нужно. Роли требуются почти
     * всегда, но EAGER давал бы N+1 при чтении списка пользователей: Hibernate выполнил бы
     * запрос за пользователями, а затем по одному запросу за ролями каждого. Вместо этого
     * все три метода чтения в репозитории берут роли явным {@code LEFT JOIN FETCH} — тем же
     * самым LEFT JOIN, что стоял в рукописном SQL до перехода на JPA.
     */
    @ElementCollection
    @CollectionTable(
            name = "app_user_role",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Column(name = "role", nullable = false)
    @Enumerated(EnumType.STRING)
    private Set<UserRole> roles = EnumSet.noneOf(UserRole.class);

    /**
     * Рестораны, которыми пользователь управляет.
     *
     * <p>Тоже коллекция значений, и по той же причине: {@code restaurant_manager} — таблица
     * связи, а не самостоятельная сущность. Хранятся идентификаторы, а не ссылки на
     * {@code Restaurant}: ресторан живёт в соседнем модуле, и связь на уровне Hibernate
     * открыла бы проход по всему графу через границу модуля.
     *
     * <p>Используется только для записи. Оба чтения — «управляет ли этим рестораном» и
     * «список его ресторанов» — идут отдельными запросами: первое вызывается из
     * {@code @PreAuthorize}, то есть до открытия транзакции, где ленивая коллекция
     * недоступна в принципе.
     */
    @ElementCollection
    @CollectionTable(
            name = "restaurant_manager",
            joinColumns = @JoinColumn(name = "user_id")
    )
    @Column(name = "restaurant_id", nullable = false)
    private Set<Long> managedRestaurantIds = new LinkedHashSet<>();

    public AppUser(String email, String passwordHash, String fullName, String phone) {
        this.email = email;
        this.passwordHash = passwordHash;
        this.fullName = fullName;
        this.phone = phone;
        this.enabled = true;
    }

    public boolean hasRole(UserRole role) {
        return roles.contains(role);
    }

    /**
     * Идемпотентно: {@link Set} сам отбрасывает повтор.
     *
     * <p>JDBC-версия добивалась того же через {@code ON CONFLICT (user_id, role) DO NOTHING} —
     * то есть повторную вставку отбрасывала база. Здесь до базы повтор просто не доходит.
     */
    public void grantRole(UserRole role) {
        roles.add(role);
    }

    public void addManagedRestaurant(Long restaurantId) {
        managedRestaurantIds.add(restaurantId);
    }

    /**
     * Коллекция отдаётся только для чтения. Внешний код не должен уметь очистить набор ролей:
     * для {@code @ElementCollection} это означало бы DELETE всех строк пользователя.
     */
    public Set<UserRole> getRoles() {
        return Collections.unmodifiableSet(roles);
    }

    @PrePersist
    void onInsert() {
        OffsetDateTime now = OffsetDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = OffsetDateTime.now();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof AppUser that && id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return AppUser.class.hashCode();
    }
}
