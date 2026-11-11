package com.jwt_service.repository;

import com.jwt_service.entity.AuthUser;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthRepository extends JpaRepository<AuthUser, Integer> {
  Optional<AuthUser> findByEmail(String email);

  boolean existsByEmail(String email);
}
