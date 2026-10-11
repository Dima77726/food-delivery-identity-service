-- Пользователи, роли, права на рестораны и журнал административных действий — в собственной
-- базе сервиса.
--
-- Итог миграций 018, 021 и 026 монолита в одной. Типы колонок совпадают с монолитными один
-- в один: данные переносятся оттуда одноразовой задачей (docker/migrations/identity-from-monolith.sh)
-- с сохранением идентификаторов — на них ссылаются заказы, корзины, отзывы и доставки
-- во всех остальных сервисах.
--
-- Начальных данных нет по той же причине, что у каталога: пользователи уже существуют
-- в базе монолита, и единственный источник — перенос.

CREATE TABLE IF NOT EXISTS app_user
(
    id            BIGSERIAL PRIMARY KEY,
    email         VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name     VARCHAR(255) NOT NULL,
    phone         VARCHAR(50),
    is_enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_app_user_email_not_blank
        CHECK (LENGTH(TRIM(email)) > 0)
);

-- Ivan@mail.ru и ivan@mail.ru — один человек: уникальность по LOWER(email).
CREATE UNIQUE INDEX IF NOT EXISTS uq_app_user_email_lower
    ON app_user (LOWER(email));

COMMENT ON TABLE app_user IS 'Пользователь платформы: клиент, владелец ресторана, курьер или администратор';
COMMENT ON COLUMN app_user.password_hash IS 'BCrypt-хеш пароля; сам пароль не хранится нигде';

CREATE TABLE IF NOT EXISTS app_user_role
(
    user_id BIGINT      NOT NULL,
    role    VARCHAR(50) NOT NULL,

    CONSTRAINT pk_app_user_role
        PRIMARY KEY (user_id, role),

    CONSTRAINT fk_app_user_role_user
        FOREIGN KEY (user_id)
            REFERENCES app_user (id)
            ON DELETE CASCADE,

    CONSTRAINT chk_app_user_role
        CHECK (role IN ('CUSTOMER', 'RESTAURANT_OWNER', 'COURIER', 'ADMIN'))
);

CREATE INDEX IF NOT EXISTS idx_app_user_role_user_id
    ON app_user_role (user_id);

-- Права на рестораны. Внешнего ключа на restaurant нет: рестораны живут в каталоге.
-- restaurant_id — идентификатор из каталога, согласованность держит порядок операций:
-- каталог назначает управляющего сразу после создания ресторана.
CREATE TABLE IF NOT EXISTS restaurant_manager
(
    user_id       BIGINT      NOT NULL,
    restaurant_id BIGINT      NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_restaurant_manager
        PRIMARY KEY (user_id, restaurant_id),

    CONSTRAINT fk_restaurant_manager_user
        FOREIGN KEY (user_id)
            REFERENCES app_user (id)
            ON DELETE CASCADE
);

COMMENT ON TABLE restaurant_manager IS 'Кто из пользователей управляет каким рестораном; рестораны — в catalog-service';

CREATE INDEX IF NOT EXISTS idx_restaurant_manager_restaurant_id
    ON restaurant_manager (restaurant_id);

-- Журнал административных действий над пользователями. Схема та же, что у журнала монолита.
CREATE TABLE IF NOT EXISTS audit_log
(
    id             BIGSERIAL PRIMARY KEY,
    actor_id       BIGINT,
    actor_email    VARCHAR(255),
    action         VARCHAR(100) NOT NULL,
    resource_type  VARCHAR(100) NOT NULL,
    resource_id    VARCHAR(100),
    outcome        VARCHAR(50)  NOT NULL,
    details        VARCHAR(2000),
    correlation_id VARCHAR(64),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_audit_log_outcome
        CHECK (outcome IN ('SUCCESS', 'FAILURE'))
);

COMMENT ON TABLE audit_log IS 'Журнал административных действий над пользователями';

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
    ON audit_log (created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_log_resource
    ON audit_log (resource_type, resource_id);
