package com.abdo.springsecurityauthjwt.repositories;

import java.util.Optional;

import com.abdo.springsecurityauthjwt.models.ERole;
import com.abdo.springsecurityauthjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;



@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}