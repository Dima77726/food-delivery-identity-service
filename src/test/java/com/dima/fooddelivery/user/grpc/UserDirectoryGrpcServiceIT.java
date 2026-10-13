package com.dima.fooddelivery.user.grpc;

import com.dima.fooddelivery.grpc.identity.v1.GetUserContactRequest;
import com.dima.fooddelivery.grpc.identity.v1.UserContact;
import com.dima.fooddelivery.grpc.identity.v1.UserDirectoryServiceGrpc;
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

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Контакт пользователя глазами сервиса уведомлений: gRPC-сервер на настоящем порту.
 *
 * <p>Без транзакции теста по той же причине, что и у {@link RestaurantAccessGrpcServiceIT}:
 * сервер отвечает из своего потока и не увидел бы незакоммиченных пользователей.
 */
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class UserDirectoryGrpcServiceIT extends AbstractIntegrationTest {

    @LocalGrpcPort
    private int grpcPort;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private ManagedChannel channel;
    private UserDirectoryServiceGrpc.UserDirectoryServiceBlockingStub directory;

    @BeforeEach
    void connect() {
        channel = ManagedChannelBuilder.forAddress("localhost", grpcPort).usePlaintext().build();
        directory = UserDirectoryServiceGrpc.newBlockingStub(channel).withDeadlineAfter(5, TimeUnit.SECONDS);
    }

    @AfterEach
    void disconnect() {
        channel.shutdownNow();
    }

    @Test
    void shouldReturnEmailNameAndEnabledFlag() {
        Long userId = testData.insertUser("contact", UserRole.CUSTOMER);

        UserContact contact = directory.getUserContact(request(userId));

        assertAll(
                () -> assertEquals(userId, contact.getUserId()),
                () -> assertTrue(contact.getEmail().startsWith("contact-")),
                () -> assertTrue(contact.getEmail().endsWith("@example.test")),
                () -> assertEquals("Test User", contact.getFullName()),
                () -> assertTrue(contact.getEnabled())
        );
    }

    /** Заблокированному пользователю контакт отдаётся с признаком: писать ему или нет, решает потребитель. */
    @Test
    void shouldReportDisabledUser() {
        Long userId = testData.insertUser("blocked", UserRole.CUSTOMER);
        jdbcTemplate.update("UPDATE app_user SET is_enabled = FALSE WHERE id = ?", userId);

        assertFalse(directory.getUserContact(request(userId)).getEnabled());
    }

    /** Нет такого пользователя — NOT_FOUND, а не пустой контакт: пустой адрес потребитель принял бы за настоящий. */
    @Test
    void shouldAnswerNotFoundForUnknownUser() {
        StatusRuntimeException error = assertThrows(
                StatusRuntimeException.class,
                () -> directory.getUserContact(request(999_999_999L))
        );

        assertEquals(Status.Code.NOT_FOUND, error.getStatus().getCode());
    }

    private static GetUserContactRequest request(long userId) {
        return GetUserContactRequest.newBuilder().setUserId(userId).build();
    }
}
