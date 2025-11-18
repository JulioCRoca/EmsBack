package com.app.emsx.repositories;

import com.app.emsx.entities.Skill;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * 🧠 SkillRepository
 * -----------------------------------------------------
 * Repositorio de acceso a datos para la entidad Skill.
 * Incluye métodos personalizados según convención de Spring Data JPA.
 */
@Repository
public interface SkillRepository extends JpaRepository<Skill, Long> {

    // ✅ Verifica duplicados por nombre
    boolean existsByName(String name);
}
