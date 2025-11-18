package com.app.emsx.repositories;

import com.app.emsx.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * UserRepository
 * -----------------------------------------------------
 * ✔ Repositorio JPA para entidad User
 * ✔ Incluye método para buscar por email
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Busca un usuario por su email (para login)
     */
    Optional<User> findByEmail(String email);
}
