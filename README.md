# food-delivery-identity-service

Сервис платформы доставки еды. Платформа целиком (docker-compose, наблюдаемость, Postman,
общая документация) — в репозитории [food-delivery-platform](https://github.com/Dima77726/food-delivery-platform);
контракты событий, gRPC и REST — в [food-delivery-contracts](https://github.com/Dima77726/food-delivery-contracts).

## Сборка

Контракты лежат в GitHub Packages, а он требует токен даже для чтения. Один раз в
`~/.m2/settings.xml`:

```xml
<servers>
  <server>
    <id>github</id>
    <username>ВАШ_GITHUB_ЛОГИН</username>
    <password>ТОКЕН_С_ПРАВОМ_read:packages</password>
  </server>
</servers>
```

```bash
./mvnw verify
```

Интеграционным тестам нужен Docker (Testcontainers).

## Образ

```bash
docker build --secret id=maven_settings,src=$HOME/.m2/settings.xml -t food-delivery-identity-service .
```

CI публикует образ в `ghcr.io/<владелец>/food-delivery-identity-service` на каждый пуш в `main` и `dev`.

## Вход через Keycloak (OIDC)

Keycloak отвечает за то, как человека опознают (форма входа, подтверждение почты, защита от перебора, при желании
второй фактор и соцсети). Владельцем пользователей, ролей и прав на рестораны остаётся платформа: токен Keycloak
**обменивается** на токен платформы, поэтому остальные сервисы не менялись.

`POST /api/v1/auth/oidc` с телом `{"token": "<access-токен Keycloak>"}` возвращает ту же пару токенов, что и `/login`.
Эндпоинт существует только при `OIDC_ENABLED=true` (также `OIDC_ISSUER`, `OIDC_JWK_SET_URI`, `OIDC_CLIENT_IDS`).

Что проверяется: подпись (RS256, ключи по JWKS), издатель, срок действия, клиент (`azp`) и **подтверждённая почта** —
по ней находится пользователь, поэтому непроверенный адрес отвергается.

Как находится пользователь: по связи (издатель, subject) в таблице `external_identity`; иначе по подтверждённой почте
(связь запоминается); иначе создаётся новый, с ролью из токена (`CUSTOMER`, `RESTAURANT_OWNER`, `COURIER`).
Роли из токена берутся **только при создании** и никогда не повышают существующего пользователя; `ADMIN` из токена не
принимается, а привязать вход через провайдера к учётной записи администратора нельзя
(`app.oidc.link-admin-accounts`). Войти по паролю в созданную так запись невозможно.
