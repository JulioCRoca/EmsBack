package com.app.emsx.repositories;

import com.app.emsx.entities.Dependent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface DependentRepository extends JpaRepository<Dependent, Long> {

    // ✅ Verifica si existe un dependiente con el mismo nombre para un empleado
    boolean existsByNameAndEmployee_Id(String name, Long employeeId);

    // ✅ Obtiene todos los dependientes de un empleado
    List<Dependent> findByEmployee_Id(Long employeeId);
}
