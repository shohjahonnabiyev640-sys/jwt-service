package com.jwt_service.service;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtServiceTest {
    private static final String SECRET = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private static final String OTHER_SECRET = "ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=";

    private final JwtService jwtService = new JwtService(SECRET, 60_000);

    @Test
    void generatedTokenContainsEmail() {
        String token = jwtService.generateToken("user@test.uz");

        assertThat(jwtService.extractEmail(token)).isEqualTo("user@test.uz");
    }

    @Test
    void expiredTokenIsRejected() {
        String token = new JwtService(SECRET, -1_000).generateToken("user@test.uz");

        assertThatThrownBy(() -> jwtService.extractEmail(token)).isInstanceOf(ExpiredJwtException.class);
    }

    @Test
    void tokenSignedWithAnotherKeyIsRejected() {
        String token = new JwtService(OTHER_SECRET, 60_000).generateToken("user@test.uz");

        assertThatThrownBy(() -> jwtService.extractEmail(token)).isInstanceOf(SignatureException.class);
    }

    @Test
    void malformedTokenIsRejected() {
        assertThatThrownBy(() -> jwtService.extractEmail("abc.def.ghi")).isInstanceOf(JwtException.class);
    }
}
