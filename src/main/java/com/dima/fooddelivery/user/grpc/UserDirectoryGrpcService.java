package com.dima.fooddelivery.user.grpc;

import com.dima.fooddelivery.common.exception.ResourceNotFoundException;
import com.dima.fooddelivery.grpc.identity.v1.GetUserContactRequest;
import com.dima.fooddelivery.grpc.identity.v1.UserContact;
import com.dima.fooddelivery.grpc.identity.v1.UserDirectoryServiceGrpc;
import com.dima.fooddelivery.user.domain.AppUser;
import com.dima.fooddelivery.user.service.UserService;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Контакт пользователя — для сервиса уведомлений.
 *
 * <p>Адрес электронной почты принадлежит пользователю, поэтому отдаёт его тот, кто владеет
 * пользователями. В событиях заказа адреса нет и быть не должно: их читают многие потребители,
 * а адрес — персональные данные. Сервис уведомлений знает получателя по номеру и спрашивает
 * контакт в момент отправки.
 *
 * <p>Отдаётся только то, что описано в контракте: адрес, имя и признак «включён». Пароль,
 * телефон и роли наружу не выходят, и добавлять их сюда «на всякий случай» нельзя.
 *
 * <p>Доступ — по mTLS и только сервисам из {@code app.grpc.security.allowed-clients}: адреса
 * пользователей не должны отдаваться каждому, кто дотянулся до порта.
 *
 * <p>В логе адрес не пишется — только номер пользователя: журнал читают шире, чем базу.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class UserDirectoryGrpcService extends UserDirectoryServiceGrpc.UserDirectoryServiceImplBase {

    private final UserService userService;

    @Override
    public void getUserContact(GetUserContactRequest request, StreamObserver<UserContact> responseObserver) {
        AppUser user;

        try {
            user = userService.requireUser(request.getUserId());
        } catch (ResourceNotFoundException exception) {
            // Не сбой: пользователя могли удалить, пока событие шло по очереди.
            log.info("Контакт не найден: userId={}", request.getUserId());
            responseObserver.onError(Status.NOT_FOUND.withDescription(exception.getMessage()).asRuntimeException());
            return;
        }

        responseObserver.onNext(UserContact.newBuilder()
                .setUserId(user.getId())
                .setEmail(user.getEmail())
                // Имя необязательно: в proto3 пустая строка и «нет значения» — одно и то же.
                .setFullName(user.getFullName() == null ? "" : user.getFullName())
                .setEnabled(user.isEnabled())
                .build());
        responseObserver.onCompleted();
    }
}
