package com.dima.fooddelivery.user.persistence;

import com.dima.fooddelivery.user.domain.AppUser;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Репозиторий пользователей на голом Hibernate: {@link EntityManager} и JPQL, без Spring Data.
 *
 * <p>Это третий из четырёх подходов, сосуществующих в проекте. Соседи для сравнения:
 * {@code RestaurantRepository} и {@code MenuCategoryRepository} — интерфейсы Spring Data,
 * реализацию которых генерирует фреймворк; {@code OrderRepository} — Spring JDBC с рукописным
 * SQL; {@code AuditLogRepository} — голый JDBC.
 *
 * <p>Отличие от Spring Data ровно одно, и оно хорошо видно ниже: методы приходится писать
 * самому. Всё остальное — те же сущности, тот же персистентный контекст, та же грязная
 * проверка, те же транзакции. Spring Data не добавляет к JPA новой семантики, она пишет
 * за вас вот этот класс.
 *
 * <p>{@code EntityManager} внедряется конструктором как обычная зависимость. Настоящий
 * менеджер сюда не попадает: Spring подставляет прокси, который на каждый вызов находит
 * экземпляр, привязанный к текущей транзакции. Без этого два метода одного сервиса работали бы
 * с разными персистентными контекстами.
 */
@Repository
@RequiredArgsConstructor
public class AppUserRepository {

    /**
     * Пользователь вместе с ролями, одним запросом.
     *
     * <p>{@code LEFT JOIN FETCH} здесь — не оптимизация, а условие работоспособности.
     * Коллекция ролей ленивая, а пользователь уезжает за границу транзакции: в JWT, в ответ
     * API, в журнал аудита. При {@code open-in-view: false} обращение к незагруженным ролям
     * там дало бы LazyInitializationException. Загруженная в транзакции коллекция остаётся
     * доступной и после отсоединения сущности.
     *
     * <p>{@code LEFT}, а не {@code INNER}: пользователь без ролей — законное состояние,
     * и он обязан находиться. Ровно тот же LEFT JOIN стоял в рукописном SQL до перехода.
     */
    private static final String SELECT_USER = """
            SELECT u FROM AppUser u
            LEFT JOIN FETCH u.roles
            """;

    private final EntityManager entityManager;

    public Optional<AppUser> findById(Long userId) {
        return single(entityManager
                .createQuery(SELECT_USER + " WHERE u.id = :userId", AppUser.class)
                .setParameter("userId", userId));
    }

    /** Поиск по e-mail без учёта регистра — так же, как работает уникальный индекс. */
    public Optional<AppUser> findByEmail(String email) {
        return single(entityManager
                .createQuery(SELECT_USER + " WHERE LOWER(u.email) = LOWER(:email)", AppUser.class)
                .setParameter("email", email));
    }

    public boolean existsByEmail(String email) {
        Long count = entityManager
                .createQuery("SELECT COUNT(u) FROM AppUser u WHERE LOWER(u.email) = LOWER(:email)", Long.class)
                .setParameter("email", email)
                .getSingleResult();

        return count > 0;
    }

    public List<AppUser> findAll() {
        return entityManager
                .createQuery(SELECT_USER + " ORDER BY u.id", AppUser.class)
                .getResultList();
    }

    /**
     * Новый пользователь.
     *
     * <p>{@code persist}, а не {@code merge}: сущность заведомо новая, и merge выполнил бы
     * лишний SELECT, проверяя, нет ли её уже в базе. Идентификатор проставляется сразу —
     * стратегия IDENTITY вынуждает Hibernate выполнить INSERT немедленно.
     */
    public AppUser save(AppUser user) {
        entityManager.persist(user);

        return user;
    }

    /**
     * Управляет ли пользователь этим рестораном.
     *
     * <p>Запрос, а не обход коллекции {@code managedRestaurantIds}, и причина не в скорости.
     * Метод вызывается из {@code @PreAuthorize}, то есть до того, как сервис откроет
     * транзакцию: ленивая коллекция в этот момент недоступна в принципе. Запрос же
     * выполняется и вне транзакции — Spring откроет для него отдельный EntityManager.
     */
    public boolean managesRestaurant(Long userId, Long restaurantId) {
        Long count = entityManager
                .createQuery("""
                        SELECT COUNT(u) FROM AppUser u
                        JOIN u.managedRestaurantIds managedId
                        WHERE u.id = :userId AND managedId = :restaurantId
                        """, Long.class)
                .setParameter("userId", userId)
                .setParameter("restaurantId", restaurantId)
                .getSingleResult();

        return count > 0;
    }

    public List<Long> findManagedRestaurantIds(Long userId) {
        return entityManager
                .createQuery("""
                        SELECT managedId FROM AppUser u
                        JOIN u.managedRestaurantIds managedId
                        WHERE u.id = :userId
                        ORDER BY managedId
                        """, Long.class)
                .setParameter("userId", userId)
                .getResultList();
    }

    /**
     * Немедленно отправляет накопленные изменения в базу.
     *
     * <p>Нужен там, где на ответ базы опирается бизнес-логика: уникальность e-mail проверяет
     * индекс {@code uq_app_user_email_lower}, и без сброса нарушение всплыло бы только
     * на коммите — то есть за пределами метода, который умеет его объяснить.
     */
    public void flush() {
        entityManager.flush();
    }

    /**
     * {@code getSingleResult} здесь не годится: он бросает исключение, когда ничего
     * не найдено, а «пользователя нет» — обычный ответ, а не сбой.
     */
    private Optional<AppUser> single(TypedQuery<AppUser> query) {
        return query.getResultList().stream().findFirst();
    }
}
