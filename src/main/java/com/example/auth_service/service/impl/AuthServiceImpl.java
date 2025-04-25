package com.example.auth_service.service;

import com.example.auth_service.dto.AuthRequest;
import com.example.auth_service.dto.AuthResponse;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.dto.UserDto;

import com.example.auth_service.exception.UserAlreadyExistsException;
import com.example.auth_service.maper.UserMapper;
import com.example.auth_service.repository.UserRepository;
import com.example.auth_service.security.JwtTokenProvider;
import com.shop.authservice.model.User;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthServiceImpl implements AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider tokenProvider;

    @Autowired
    private UserMapper userMapper;


    @Override
    public AuthResponse authenticateUser(AuthRequest authRequest) {
        // Аутентификация через email и пароль
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authRequest.getEmail(), authRequest.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.generateToken(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername()).orElseThrow();

        // Используем маппер для создания ответа
        return userMapper.toAuthResponse(user, jwt);
    }

    @Override
    @Transactional
    public UserDto registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            throw new UserAlreadyExistsException("Email is already in use!");
        }

        // Создаем нового пользователя с помощью маппера
        User user = userMapper.toUser(registerRequest, passwordEncoder);
        User savedUser = userRepository.save(user);

        // Преобразуем сущность в DTO для ответа
        return userMapper.toUserDto(savedUser);
    }

    @Override
    public UserDto getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        User user = userRepository.findByEmail(userDetails.getUsername()).orElseThrow();

        // Преобразуем текущего пользователя в DTO
        return userMapper.toUserDto(user);
    }
}