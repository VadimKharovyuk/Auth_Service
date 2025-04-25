package com.example.auth_service.service;



import com.example.auth_service.dto.AuthRequest;
import com.example.auth_service.dto.AuthResponse;
import com.example.auth_service.dto.RegisterRequest;
import com.example.auth_service.dto.UserDto;

public interface AuthService {
    AuthResponse authenticateUser(AuthRequest authRequest);
    UserDto registerUser(RegisterRequest registerRequest);
    UserDto getCurrentUser();
}
