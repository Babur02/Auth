package baris.RoleBasedAuthBackEnd.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import baris.RoleBasedAuthBackEnd.model.User;

public interface UserRepository extends JpaRepository<User, Integer> {
    Optional<User> findByUsername(String username);
}
