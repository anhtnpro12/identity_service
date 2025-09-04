package com.anhtrinhnam02.identity_service.controller;

import com.anhtrinhnam02.identity_service.dto.request.ApiResponse;
import com.anhtrinhnam02.identity_service.dto.request.UserCreationRequest;
import com.anhtrinhnam02.identity_service.dto.request.UserUpdateRequest;
import com.anhtrinhnam02.identity_service.dto.response.UserResponse;
import com.anhtrinhnam02.identity_service.entity.User;
import com.anhtrinhnam02.identity_service.service.UserService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserController {
    UserService userService;

    @PostMapping
    ApiResponse<User> createUser(@RequestBody @Valid UserCreationRequest request) {
        ApiResponse<User> response = new ApiResponse<>();

        response.setResult(userService.createUser(request));

        return response;
    }

    @GetMapping
    List<User> getUsers() {
        return userService.getUsers();
    }

    @GetMapping("/{userId}")
    UserResponse getUser(@PathVariable("userId") String userId) {
        return userService.getUser(userId);
    }

    @PutMapping("/{userId}")
    UserResponse updateUser(@PathVariable("userId") String userId, @RequestBody UserUpdateRequest request) {
        return userService.updateUser(userId, request);
    }

    @DeleteMapping("/{userId}")
    String deleteUser(@PathVariable("userId") String userId) {
        userService.deleteUser(userId);

        return "User has been deleted";
    }
}
