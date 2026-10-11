package com.dima.fooddelivery.user.grpc;

import com.dima.fooddelivery.common.exception.ResourceNotFoundException;
import com.dima.fooddelivery.grpc.identity.v1.AssignRestaurantManagerRequest;
import com.dima.fooddelivery.grpc.identity.v1.AssignRestaurantManagerResponse;
import com.dima.fooddelivery.grpc.identity.v1.CheckRestaurantAccessRequest;
import com.dima.fooddelivery.grpc.identity.v1.CheckRestaurantAccessResponse;
import com.dima.fooddelivery.grpc.identity.v1.RestaurantAccessServiceGrpc;
import com.dima.fooddelivery.user.service.UserService;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Права на рестораны — для каталога.
 *
 * <p>Связь «пользователь — ресторан» осталась здесь, хотя рестораны уехали: это факт о правах
 * пользователя, а пользователи живут в монолите. Каталог спрашивает, а не держит копию —
 * копии прав расходятся, и расхождение здесь означало бы доступ к чужому ресторану.
 *
 * <p>Вход открыт без аутентификации: gRPC-порт не публикуется наружу и доступен только
 * внутри сети сервисов. Следующий шаг — mTLS, чтобы сеть перестала быть единственной защитой.
 * Тем более что {@code AssignRestaurantManager} выдаёт права, и вызвать его может любой,
 * кто дотянулся до порта.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RestaurantAccessGrpcService extends RestaurantAccessServiceGrpc.RestaurantAccessServiceImplBase {

    private final UserService userService;

    @Override
    public void checkRestaurantAccess(
            CheckRestaurantAccessRequest request,
            StreamObserver<CheckRestaurantAccessResponse> responseObserver
    ) {
        boolean manages = userService.managesRestaurant(request.getUserId(), request.getRestaurantId());

        responseObserver.onNext(CheckRestaurantAccessResponse.newBuilder().setManages(manages).build());
        responseObserver.onCompleted();
    }

    /** Идемпотентно: повторное назначение не дублирует связь — это множество. */
    @Override
    public void assignRestaurantManager(
            AssignRestaurantManagerRequest request,
            StreamObserver<AssignRestaurantManagerResponse> responseObserver
    ) {
        try {
            userService.assignRestaurantManager(request.getUserId(), request.getRestaurantId());
        } catch (ResourceNotFoundException exception) {
            responseObserver.onError(Status.NOT_FOUND.withDescription(exception.getMessage()).asRuntimeException());
            return;
        }

        responseObserver.onNext(AssignRestaurantManagerResponse.getDefaultInstance());
        responseObserver.onCompleted();
    }
}
