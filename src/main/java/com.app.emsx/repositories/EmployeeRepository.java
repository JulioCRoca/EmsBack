package com.app.emsx.repositories;

import com.app.emsx.entities.Employee;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface EmployeeRepository extends JpaRepository<Employee, Long> {

    // ✅ Verifica duplicados por email
    boolean existsByEmail(String email);

    // ✅ Cuenta empleados agrupados por departamento (para dashboard)
    @Query("SELECT e.department.name, COUNT(e) FROM Employee e GROUP BY e.department.name")
    List<Object[]> countEmployeesByDepartment();
}
