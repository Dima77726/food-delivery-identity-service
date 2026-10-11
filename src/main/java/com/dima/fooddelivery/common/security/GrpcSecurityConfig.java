package com.dima.fooddelivery.common.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.grpc.server.GlobalServerInterceptor;
import org.springframework.grpc.server.security.AuthenticationProcessInterceptor;
import org.springframework.grpc.server.security.GrpcSecurity;

/**
 * Правила доступа к gRPC-серверу каталога.
 *
 * <p><b>Почему класс вообще нужен.</b> Spring gRPC, увидев Spring Security в classpath, по
 * умолчанию закрывает весь gRPC-сервер аутентификацией. Способа аутентифицироваться у
 * вызывающего сервиса нет, и каждый вызов получал бы UNAUTHENTICATED — монолит не смог бы
 * положить в корзину ни одного блюда. Это поймал {@code CatalogGrpcServiceIT}, а не стенд.
 *
 * <p><b>Почему permitAll — и почему это временно.</b> Сейчас gRPC-порт защищён сетью:
 * он не публикуется наружу и доступен только из сети сервисов. Это осознанный промежуточный
 * шаг, а не конечное состояние. Следующий — взаимный TLS: каждый сервис предъявляет
 * сертификат, и сервер проверяет, кто именно к нему пришёл. Тогда здесь появится правило
 * вида «CatalogService — только для order-service», а не «всем, кто в сети».
 */
@Configuration(proxyBeanMethods = false)
public class GrpcSecurityConfig {

    @Bean
    @GlobalServerInterceptor
    AuthenticationProcessInterceptor grpcSecurityInterceptor(GrpcSecurity grpc) throws Exception {
        return grpc
                .authorizeRequests(requests -> requests.allRequests().permitAll())
                .build();
    }
}
