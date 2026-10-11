package com.dima.fooddelivery.common.exception;

/**
 * Refresh-токен не подошёл: неизвестен, истёк, отозван или уже обменян. Причина наружу
 * не сообщается — клиенту в любом случае остаётся одно: войти заново.
 */
public class InvalidRefreshTokenException extends RuntimeException {

    public InvalidRefreshTokenException() {
        super("Сессия недействительна, войдите заново");
    }
}
