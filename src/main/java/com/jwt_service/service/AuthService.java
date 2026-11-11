package com.jwt_service.service;

import com.jwt_service.dto.AuthTokenDto;
import com.jwt_service.dto.AuthUserLoginDto;
import com.jwt_service.dto.AuthUserRegistrDto;

public interface AuthService {

    void saveUser( AuthUserRegistrDto authUserRegistrDto);

    AuthTokenDto login(AuthUserLoginDto authUserLoginDto);
}
