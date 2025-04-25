package com.example.auth_service.maper;

import com.example.auth_service.dto.AuthResponse;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.dto.UserDto;
import com.example.auth_service.model.Role;
import com.example.auth_service.model.User;
import com.example.auth_service.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class UserMapper {

    @Autowired
    private RoleRepository roleRepository;

    public UserDto toUserDto(User user) {
        if (user == null) {
            return null;
        }

        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());

        return new UserDto(
                user.getId(),
                user.getEmail(),
                roles
        );
    }

    public AuthResponse toAuthResponse(User user, String jwt) {
        List<String> roles = user.getRoles().stream()
                .map(role -> role.getName().name())
                .collect(Collectors.toList());

        return new AuthResponse(
                jwt,
                user.getId(),
                user.getEmail(),
                roles
        );
    }

    public User toUser(RegisterRequest registerRequest, PasswordEncoder passwordEncoder) {
        if (registerRequest == null) {
            return null;
        }

        User user = new User();
        user.setEmail(registerRequest.getEmail());
        user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));

        Set<Role> roles = new HashSet<>();

        // Получаем существующую роль USER из базы данных
        roleRepository.findByName(Role.ERole.ROLE_USER)
                .ifPresent(roles::add);

        // Если в запросе указана роль ADMIN, добавляем её из базы данных
        if (registerRequest.getRoles() != null && registerRequest.getRoles().contains("ADMIN")) {
            roleRepository.findByName(Role.ERole.ROLE_ADMIN)
                    .ifPresent(roles::add);
        }

        user.setRoles(roles);
        return user;
    }
}