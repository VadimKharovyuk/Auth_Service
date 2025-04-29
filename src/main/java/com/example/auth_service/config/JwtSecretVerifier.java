package com.example.auth_service.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtSecretVerifier {
    @Value("${jwt.secret:#{null}}") // Проверяем оба возможных имени
    private String jwtSecret;

    @Value("${application.security.jwt.secret-key:#{null}}")
    private String jwtSecretKey;

    private final Logger logger = LoggerFactory.getLogger(JwtSecretVerifier.class);

    @PostConstruct
    public void verifySecret() {
        String actualSecret = jwtSecret != null ? jwtSecret : jwtSecretKey;

        if (actualSecret == null) {
            logger.error("JWT SECRET KEY IS NOT CONFIGURED!");
        } else {
            logger.info("JWT Secret Key Hash: {}", actualSecret.hashCode());
            logger.info("JWT Secret Key First 4 chars: {}", actualSecret.substring(0, 4));
        }
    }
}