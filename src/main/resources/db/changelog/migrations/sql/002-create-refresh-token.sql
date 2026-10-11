-- Refresh-токены. Сам токен не хранится — только его SHA-256: утечка таблицы не даёт
-- ни одного рабочего токена. Медленный хеш вроде BCrypt здесь не нужен: токен — 256 случайных
-- бит, а не пароль, перебирать его по словарю бессмысленно.
--
-- Токены живут цепочками (family_id). Каждый обмен помечает старый токен использованным
-- и выдаёт новый в той же цепочке. Повторное предъявление уже использованного токена значит,
-- что копий две — у владельца и у того, кто его украл, — и цепочка отзывается целиком.

CREATE TABLE IF NOT EXISTS refresh_token
(
    id         BIGSERIAL PRIMARY KEY,
    token_hash CHAR(64)    NOT NULL,
    user_id    BIGINT      NOT NULL,
    family_id  UUID        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at    TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,

    CONSTRAINT uq_refresh_token_hash
        UNIQUE (token_hash),

    CONSTRAINT fk_refresh_token_user
        FOREIGN KEY (user_id)
            REFERENCES app_user (id)
            ON DELETE CASCADE
);

COMMENT ON TABLE refresh_token IS 'Refresh-токены: SHA-256 значения, цепочка ротации, срок и отзыв';
COMMENT ON COLUMN refresh_token.used_at IS 'Когда токен обменяли на новый; повторное предъявление — признак кражи';

CREATE INDEX IF NOT EXISTS idx_refresh_token_family_id
    ON refresh_token (family_id);

CREATE INDEX IF NOT EXISTS idx_refresh_token_user_id
    ON refresh_token (user_id);

CREATE INDEX IF NOT EXISTS idx_refresh_token_expires_at
    ON refresh_token (expires_at);
