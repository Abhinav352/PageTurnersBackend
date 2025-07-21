package com.example.PageTurners.repository;

import com.example.PageTurners.models.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByUserName(String userName);
    Optional<AppUser> findByEmailAndProvider(String email, String provider);
}

