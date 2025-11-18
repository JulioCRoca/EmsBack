package com.app.emsx.mappers;

import com.app.emsx.dtos.employeeSkill.EmployeeSkillResponse;
import com.app.emsx.entities.Employee;
import com.app.emsx.entities.Skill;
import org.springframework.stereotype.Component;

/**
 * 🧠 EmployeeSkillMapper
 * -----------------------------------------------------
 * Mapper manual entre Employee y Skill para construir
 * respuestas empresariales sin recursividad.
 */
@Component
public class EmployeeSkillMapper {

    /**
     * ✅ Convierte un Employee y un Skill en una respuesta de asignación.
     */
    public EmployeeSkillResponse toResponse(Employee employee, Skill skill, String message) {
        return EmployeeSkillResponse.builder()
                .employeeId(employee.getId())
                .employeeFullName(employee.getFirstName() + " " + employee.getLastName())
                .skillId(skill.getId())
                .skillName(skill.getName())
                .message(message)
                .build();
    }
}
