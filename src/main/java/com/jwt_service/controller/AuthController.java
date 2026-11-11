package com.jwt_service.controller;


import com.jwt_service.dto.AuthTokenDto;
import com.jwt_service.dto.AuthUserLoginDto;
import com.jwt_service.dto.AuthUserRegistrDto;
import com.jwt_service.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {


    private final AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<Void> registerUser(@Valid @RequestBody AuthUserRegistrDto dto){
    authService.saveUser(dto);
     return ResponseEntity.noContent().build();
    }

    @PostMapping("/login")
    public ResponseEntity<AuthTokenDto> login(@Valid @RequestBody AuthUserLoginDto dto){
        return ResponseEntity.ok(authService.login(dto));
    }


}
