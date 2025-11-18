package com.app.emsx.services;

import com.app.emsx.dtos.employeeSkill.EmployeeSkillRequest;
import com.app.emsx.dtos.employeeSkill.EmployeeSkillResponse;
import java.util.List;

/**
 * 🔗 EmployeeSkillService
 * -----------------------------------------------------
 * Define las operaciones de negocio sobre la relación Many-To-Many
 * entre empleados y habilidades.
 */
public interface EmployeeSkillService {

    /**
     * ✅ Asigna una habilidad a un empleado.
     * Lanza BusinessRuleException si ya existe la relación.
     */
    EmployeeSkillResponse assignSkill(EmployeeSkillRequest request);

    /**
     * ✅ Elimina una habilidad de un empleado.
     * Lanza BusinessRuleException si no existe la relación.
     */
    EmployeeSkillResponse removeSkill(EmployeeSkillRequest request);

    /**
     * ✅ Lista todas las habilidades de un empleado.
     */
    List<EmployeeSkillResponse> findSkillsByEmployee(Long employeeId);

    /**
     * ✅ Lista todos los empleados que poseen una habilidad específica.
     */
    List<EmployeeSkillResponse> findEmployeesBySkill(Long skillId);
    public List<EmployeeSkillResponse> getAllEmployeeSkills();
}
