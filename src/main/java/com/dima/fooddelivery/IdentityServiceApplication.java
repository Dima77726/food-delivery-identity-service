package com.dima.fooddelivery;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Сервис пользователей: регистрация, вход, роли, права на рестораны и выпуск токенов.
 *
 * <p>Класс в корневом пакете по той же причине, что у каталога: модуль {@code user} переехал
 * из монолита со своими пакетами, и сканирование от корня находит его без правок.
 */
@SpringBootApplication
public class IdentityServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(IdentityServiceApplication.class, args);
    }
}
