package com.jwt_service.service;

import com.jwt_service.dto.AuthTokenDto;
import com.jwt_service.dto.AuthUserLoginDto;
import com.jwt_service.dto.AuthUserRegistrDto;
import com.jwt_service.entity.AuthUser;
import com.jwt_service.entity.Role;
import com.jwt_service.exception.EmailAlreadyExistsException;
import com.jwt_service.repository.AuthRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Locale;

@Service
@RequiredArgsConstructor
public class AuthUserImpl implements AuthService {
    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;


    @Override
    public void saveUser(AuthUserRegistrDto dto) {
        String email = normalizeEmail(dto.getEmail());
        if (authRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException();
        }

        AuthUser authUser = new AuthUser();
        authUser.setFullName(dto.getFullName());
        authUser.setEmail(email);
        authUser.setPassword(passwordEncoder.encode(dto.getPassword()));
        authUser.setRole(Role.USER);
        authRepository.save(authUser);
    }

    @Override
    public AuthTokenDto login(AuthUserLoginDto dto) {
        String email = normalizeEmail(dto.getEmail());
        authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(email, dto.getPassword()));
        return new AuthTokenDto(jwtService.generateToken(email), "Bearer");
    }

    private String normalizeEmail(String email) {
        return email.toLowerCase(Locale.ROOT);
    }

}
