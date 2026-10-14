-- Связь пользователя платформы с учётной записью во внешнем провайдере (Keycloak).
-- Ключ связи - пара (издатель, subject), а не e-mail: адрес в провайдере можно сменить, а subject
-- остаётся тем же, и после смены адреса человек не превратится в нового пользователя.
CREATE TABLE IF NOT EXISTS external_identity
(
    issuer     VARCHAR(255) NOT NULL,
    subject    VARCHAR(255) NOT NULL,
    user_id    BIGINT       NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT pk_external_identity
        PRIMARY KEY (issuer, subject),

    CONSTRAINT fk_external_identity_user
        FOREIGN KEY (user_id)
            REFERENCES app_user (id)
            ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_external_identity_user_id
    ON external_identity (user_id);

COMMENT ON TABLE external_identity IS 'Привязка пользователя к учётной записи во внешнем OIDC-провайдере';
