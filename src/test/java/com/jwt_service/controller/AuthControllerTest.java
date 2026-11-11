package com.jwt_service.controller;

import com.jwt_service.config.SecurityConfig;
import com.jwt_service.dto.AuthTokenDto;
import com.jwt_service.entity.AuthUser;
import com.jwt_service.entity.Role;
import com.jwt_service.exception.EmailAlreadyExistsException;
import com.jwt_service.repository.AuthRepository;
import com.jwt_service.service.AuthService;
import com.jwt_service.service.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
@Import({SecurityConfig.class, JwtService.class})
@TestPropertySource(properties = {
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "jwt.expiration-ms=60000"
})
class AuthControllerTest {
    private static final String VALID_REGISTER =
            "{\"fullName\":\"Ali Valiyev\",\"email\":\"ali@test.uz\",\"password\":\"password123\"}";
    private static final String VALID_LOGIN = "{\"email\":\"ali@test.uz\",\"password\":\"password123\"}";

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JwtService jwtService;
    @MockitoBean
    private AuthService authService;
    @MockitoBean
    private AuthRepository authRepository;

    @Test
    void registerReturnsNoContent() throws Exception {
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(VALID_REGISTER))
                .andExpect(status().isNoContent());
        verify(authService).saveUser(any());
    }

    @Test
    void registerWithInvalidFieldsReturnsValidationErrors() throws Exception {
        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"fullName\":\"\",\"email\":\"bad\",\"password\":\"1\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors.fullName").exists())
                .andExpect(jsonPath("$.errors.email").exists())
                .andExpect(jsonPath("$.errors.password").exists());
    }

    @Test
    void registerWithExistingEmailReturnsConflict() throws Exception {
        doThrow(new EmailAlreadyExistsException()).when(authService).saveUser(any());

        mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(VALID_REGISTER))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.detail").value("Email is already registered"));
    }

    @Test
    void loginReturnsToken() throws Exception {
        when(authService.login(any())).thenReturn(new AuthTokenDto("token", "Bearer"));

        mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(VALID_LOGIN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("token"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"));
    }

    @Test
    void loginWithBadCredentialsReturnsUnauthorized() throws Exception {
        when(authService.login(any())).thenThrow(new BadCredentialsException("Bad credentials"));

        mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(VALID_LOGIN))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.detail").value("Invalid email or password"));
    }

    @Test
    void protectedEndpointWithoutTokenReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/protected"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointWithInvalidTokenReturnsUnauthorized() throws Exception {
        mockMvc.perform(get("/api/protected").header("Authorization", "Bearer abc.def.ghi"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void protectedEndpointWithValidTokenPassesSecurity() throws Exception {
        when(authRepository.findByEmail("ali@test.uz")).thenReturn(Optional.of(
                AuthUser.builder().id(1).fullName("Ali").email("ali@test.uz").password("hashed").role(Role.USER).build()));

        mockMvc.perform(get("/api/protected").header("Authorization", "Bearer " + jwtService.generateToken("ali@test.uz")))
                .andExpect(status().isNotFound());
    }

    @Test
    void validTokenForDeletedUserReturnsUnauthorized() throws Exception {
        when(authRepository.findByEmail("ghost@test.uz")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/protected").header("Authorization", "Bearer " + jwtService.generateToken("ghost@test.uz")))
                .andExpect(status().isUnauthorized());
    }
}
