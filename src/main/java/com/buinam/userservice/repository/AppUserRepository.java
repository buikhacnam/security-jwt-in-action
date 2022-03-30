package com.buinam.userservice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.buinam.userservice.model.AppUser;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
