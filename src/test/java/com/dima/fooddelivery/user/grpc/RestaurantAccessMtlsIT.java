package com.dima.fooddelivery.user.grpc;

import com.dima.fooddelivery.grpc.identity.v1.CheckRestaurantAccessRequest;
import com.dima.fooddelivery.grpc.identity.v1.RestaurantAccessServiceGrpc;
import com.dima.fooddelivery.support.AbstractIntegrationTest;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.grpc.test.autoconfigure.LocalGrpcPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Права на рестораны под взаимным TLS: спрашивать их могут монолит и каталог — и больше никто.
 *
 * <p>Здесь ставка выше, чем у каталога: {@code AssignRestaurantManager} выдаёт права. Без mTLS
 * любой, кто дотянулся до порта, назначил бы себя управляющим чужого ресторана.
 */
@ActiveProfiles("grpc-tls")
@TestPropertySource(properties = {
        "GRPC_TLS_CERTIFICATE=classpath:grpc-tls/identity-service.crt",
        "GRPC_TLS_PRIVATE_KEY=classpath:grpc-tls/identity-service.key",
        "GRPC_TLS_CA=classpath:grpc-tls/ca.crt"
})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class RestaurantAccessMtlsIT extends AbstractIntegrationTest {

    @LocalGrpcPort
    private int grpcPort;

    private final List<ManagedChannel> channels = new ArrayList<>();

    @AfterEach
    void closeChannels() {
        channels.forEach(ManagedChannel::shutdownNow);
    }

    @ParameterizedTest
    @ValueSource(strings = {"core", "catalog-service"})
    void shouldAnswerAllowedServices(String service) throws IOException {
        boolean manages = accessAs(service).checkRestaurantAccess(request()).getManages();

        assertFalse(manages, "ответ дошёл: незнакомый пользователь ничем не управляет");
    }

    @Test
    void shouldDenyServiceThatIsNotAllowed() throws IOException {
        StatusRuntimeException error = assertThrows(
                StatusRuntimeException.class,
                () -> accessAs("intruder").checkRestaurantAccess(request())
        );

        assertEquals(Status.Code.PERMISSION_DENIED, error.getStatus().getCode());
    }

    private RestaurantAccessServiceGrpc.RestaurantAccessServiceBlockingStub accessAs(String service) throws IOException {
        ManagedChannel channel = NettyChannelBuilder.forAddress("localhost", grpcPort)
                .sslContext(GrpcSslContexts.forClient()
                        .keyManager(resource(service + ".crt"), resource(service + ".key"))
                        .trustManager(resource("ca.crt"))
                        .build())
                .build();
        channels.add(channel);

        return RestaurantAccessServiceGrpc.newBlockingStub(channel).withDeadlineAfter(10, TimeUnit.SECONDS);
    }

    private InputStream resource(String name) throws IOException {
        return new ClassPathResource("grpc-tls/" + name).getInputStream();
    }

    private CheckRestaurantAccessRequest request() {
        return CheckRestaurantAccessRequest.newBuilder().setUserId(Long.MAX_VALUE).setRestaurantId(1).build();
    }
}
