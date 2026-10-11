package com.dima.fooddelivery.user.grpc;

import com.dima.fooddelivery.grpc.identity.v1.AssignRestaurantManagerRequest;
import com.dima.fooddelivery.grpc.identity.v1.CheckRestaurantAccessRequest;
import com.dima.fooddelivery.grpc.identity.v1.RestaurantAccessServiceGrpc;
import com.dima.fooddelivery.support.AbstractIntegrationTest;
import com.dima.fooddelivery.user.domain.UserRole;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.grpc.test.autoconfigure.LocalGrpcPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Права на рестораны глазами каталога: gRPC-сервер монолита на настоящем порту.
 *
 * <p>Без транзакции теста: сервер отвечает из своего потока и не увидел бы незакоммиченных
 * пользователей. Изоляцию дают уникальные пользователи и идентификаторы ресторанов.
 */
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class RestaurantAccessGrpcServiceIT extends AbstractIntegrationTest {

    @LocalGrpcPort
    private int grpcPort;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private ManagedChannel channel;
    private RestaurantAccessServiceGrpc.RestaurantAccessServiceBlockingStub access;

    @BeforeEach
    void connect() {
        channel = ManagedChannelBuilder.forAddress("localhost", grpcPort).usePlaintext().build();
        access = RestaurantAccessServiceGrpc.newBlockingStub(channel).withDeadlineAfter(5, TimeUnit.SECONDS);
    }

    @AfterEach
    void disconnect() {
        channel.shutdownNow();
    }

    /**
     * Ровно то, что делает каталог при создании ресторана: назначает создателя и сразу
     * проверяет его права. Ресторан в базе монолита не нужен — он живёт в каталоге.
     */
    @Test
    void shouldAssignManagerAndGrantOwnerRole() {
        Long userId = testData.insertUser("grpc-owner", UserRole.CUSTOMER);
        long restaurantId = uniqueRestaurantId();

        access.assignRestaurantManager(request(userId, restaurantId));

        List<String> roles = jdbcTemplate.queryForList(
                "SELECT role FROM app_user_role WHERE user_id = ?",
                String.class,
                userId
        );

        assertAll(
                () -> assertTrue(access.checkRestaurantAccess(check(userId, restaurantId)).getManages()),
                () -> assertTrue(roles.contains(UserRole.RESTAURANT_OWNER.name()), "управляющий получает роль владельца")
        );
    }

    /** Повтор после таймаута — штатная ситуация в сети. Он обязан завершиться успехом. */
    @Test
    void shouldAssignManagerIdempotently() {
        Long userId = testData.insertUser("grpc-repeat", UserRole.RESTAURANT_OWNER);
        long restaurantId = uniqueRestaurantId();

        access.assignRestaurantManager(request(userId, restaurantId));
        access.assignRestaurantManager(request(userId, restaurantId));

        Integer links = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM restaurant_manager WHERE user_id = ? AND restaurant_id = ?",
                Integer.class,
                userId,
                restaurantId
        );

        assertEquals(1, links);
    }

    @Test
    void shouldNotGrantAccessToForeignRestaurant() {
        Long owner = testData.insertUser("grpc-own", UserRole.RESTAURANT_OWNER);
        Long stranger = testData.insertUser("grpc-stranger", UserRole.RESTAURANT_OWNER);
        long restaurantId = uniqueRestaurantId();

        access.assignRestaurantManager(request(owner, restaurantId));

        assertFalse(access.checkRestaurantAccess(check(stranger, restaurantId)).getManages());
    }

    @Test
    void shouldAnswerNotFoundForUnknownUser() {
        StatusRuntimeException error = assertThrows(
                StatusRuntimeException.class,
                () -> access.assignRestaurantManager(request(Long.MAX_VALUE, uniqueRestaurantId()))
        );

        assertEquals(Status.Code.NOT_FOUND, error.getStatus().getCode());
    }

    /** Идентификаторы далеко за пределами тех, что выдаст база: ресторанов здесь нет вовсе. */
    private long uniqueRestaurantId() {
        return 1_000_000_000L + testData.uniqueSuffix() % 1_000_000_000L;
    }

    private AssignRestaurantManagerRequest request(long userId, long restaurantId) {
        return AssignRestaurantManagerRequest.newBuilder().setUserId(userId).setRestaurantId(restaurantId).build();
    }

    private CheckRestaurantAccessRequest check(long userId, long restaurantId) {
        return CheckRestaurantAccessRequest.newBuilder().setUserId(userId).setRestaurantId(restaurantId).build();
    }
}
