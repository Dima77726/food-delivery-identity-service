-- Ключи API партнёров: касса ресторана или его собственная система ходит в платформу без пароля
-- владельца. В базе — только SHA-256 секрета: утечка таблицы не даёт ни одного рабочего ключа.
-- Префикс — открытая часть ключа: по нему ключ находится в базе и узнаётся в списке и логах.
CREATE TABLE IF NOT EXISTS partner_api_key
(
    id           BIGSERIAL    PRIMARY KEY,
    user_id      BIGINT       NOT NULL,
    name         VARCHAR(100) NOT NULL,
    prefix       VARCHAR(16)  NOT NULL,
    secret_hash  CHAR(64)     NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,

    CONSTRAINT uq_partner_api_key_prefix UNIQUE (prefix),

    CONSTRAINT fk_partner_api_key_user
        FOREIGN KEY (user_id)
            REFERENCES app_user (id)
            ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_partner_api_key_user_id
    ON partner_api_key (user_id);

COMMENT ON TABLE partner_api_key IS 'Ключи API партнёров: только хеш секрета, отзыв - отметкой revoked_at';
