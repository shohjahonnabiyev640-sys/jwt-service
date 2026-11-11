package com.jwt_service.service;

import com.jwt_service.dto.AuthTokenDto;
import com.jwt_service.dto.AuthUserLoginDto;
import com.jwt_service.dto.AuthUserRegistrDto;
import com.jwt_service.entity.AuthUser;
import com.jwt_service.entity.Role;
import com.jwt_service.exception.EmailAlreadyExistsException;
import com.jwt_service.repository.AuthRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthUserImplTest {
    @Mock
    private AuthRepository authRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private JwtService jwtService;
    @InjectMocks
    private AuthUserImpl authService;

    @Test
    void saveUserStoresNormalizedEmailEncodedPasswordAndUserRole() {
        when(authRepository.existsByEmail("ali@test.uz")).thenReturn(false);
        when(passwordEncoder.encode("password123")).thenReturn("hashed");

        authService.saveUser(new AuthUserRegistrDto("Ali Valiyev", "Ali@Test.UZ", "password123"));

        ArgumentCaptor<AuthUser> saved = ArgumentCaptor.forClass(AuthUser.class);
        verify(authRepository).save(saved.capture());
        assertThat(saved.getValue().getEmail()).isEqualTo("ali@test.uz");
        assertThat(saved.getValue().getPassword()).isEqualTo("hashed");
        assertThat(saved.getValue().getFullName()).isEqualTo("Ali Valiyev");
        assertThat(saved.getValue().getRole()).isEqualTo(Role.USER);
    }

    @Test
    void saveUserRejectsExistingEmail() {
        when(authRepository.existsByEmail("ali@test.uz")).thenReturn(true);

        assertThatThrownBy(() -> authService.saveUser(new AuthUserRegistrDto("Ali", "ALI@test.uz", "password123")))
                .isInstanceOf(EmailAlreadyExistsException.class);
        verify(authRepository, never()).save(any());
    }

    @Test
    void loginAuthenticatesWithNormalizedEmailAndReturnsBearerToken() {
        when(jwtService.generateToken("ali@test.uz")).thenReturn("token");

        AuthTokenDto result = authService.login(new AuthUserLoginDto("Ali@Test.uz", "password123"));

        ArgumentCaptor<Authentication> auth = ArgumentCaptor.forClass(Authentication.class);
        verify(authenticationManager).authenticate(auth.capture());
        assertThat(auth.getValue().getName()).isEqualTo("ali@test.uz");
        assertThat(auth.getValue().getCredentials()).isEqualTo("password123");
        assertThat(result.getAccessToken()).isEqualTo("token");
        assertThat(result.getTokenType()).isEqualTo("Bearer");
    }

    @Test
    void loginWithBadCredentialsDoesNotIssueToken() {
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() -> authService.login(new AuthUserLoginDto("ali@test.uz", "wrong")))
                .isInstanceOf(BadCredentialsException.class);
        verify(jwtService, never()).generateToken(anyString());
    }
}
