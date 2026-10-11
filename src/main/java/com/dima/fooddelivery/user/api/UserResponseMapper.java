package com.dima.fooddelivery.user.api;

import com.dima.fooddelivery.user.domain.AppUser;

import java.util.List;

public final class UserResponseMapper {

    public static UserResponse toResponse(AppUser user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getFullName(),
                user.getPhone(),
                user.isEnabled(),
                user.getRoles(),
                user.getCreatedAt()
        );
    }

    public static List<UserResponse> toResponses(List<AppUser> users) {
        return users.stream().map(UserResponseMapper::toResponse).toList();
    }

    private UserResponseMapper() {
    }
}
