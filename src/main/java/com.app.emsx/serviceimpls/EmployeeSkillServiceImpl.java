package com.app.emsx.serviceimpls;

import com.app.emsx.dtos.employeeSkill.EmployeeSkillRequest;
import com.app.emsx.dtos.employeeSkill.EmployeeSkillResponse;
import com.app.emsx.entities.Employee;
import com.app.emsx.entities.Skill;
import com.app.emsx.exceptions.BusinessRuleException;
import com.app.emsx.exceptions.ResourceNotFoundException;
import com.app.emsx.mappers.EmployeeSkillMapper;
import com.app.emsx.repositories.EmployeeRepository;
import com.app.emsx.repositories.SkillRepository;
import com.app.emsx.services.EmployeeSkillService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 🔗 EmployeeSkillServiceImpl
 * -----------------------------------------------------
 * Implementa la lógica de negocio para la relación ManyToMany
 * entre empleados y habilidades, garantizando integridad y consistencia.
 */
@Service
@RequiredArgsConstructor
@Transactional
public class EmployeeSkillServiceImpl implements EmployeeSkillService {

    private final EmployeeRepository employeeRepository;
    private final SkillRepository skillRepository;
    private final EmployeeSkillMapper mapper;

    /**
     * ✅ Asigna una habilidad a un empleado
     */
    @Override
    public EmployeeSkillResponse assignSkill(EmployeeSkillRequest request) {
        Employee employee = employeeRepository.findById(request.getEmployeeId())
                .orElseThrow(() -> new ResourceNotFoundException("Empleado no encontrado con ID: " + request.getEmployeeId()));

        Skill skill = skillRepository.findById(request.getSkillId())
                .orElseThrow(() -> new ResourceNotFoundException("Habilidad no encontrada con ID: " + request.getSkillId()));

        if (employee.getSkills().contains(skill)) {
            throw new BusinessRuleException("La habilidad ya está asignada al empleado.");
        }

        employee.getSkills().add(skill);
        employeeRepository.save(employee);

        return mapper.toResponse(employee, skill, "Habilidad asignada exitosamente");
    }

    /**
     * ✅ Elimina una habilidad asignada a un empleado
     */
    @Override
    public EmployeeSkillResponse removeSkill(EmployeeSkillRequest request) {
        Employee employee = employeeRepository.findById(request.getEmployeeId())
                .orElseThrow(() -> new ResourceNotFoundException("Empleado no encontrado con ID: " + request.getEmployeeId()));

        Skill skill = skillRepository.findById(request.getSkillId())
                .orElseThrow(() -> new ResourceNotFoundException("Habilidad no encontrada con ID: " + request.getSkillId()));

        if (!employee.getSkills().contains(skill)) {
            throw new BusinessRuleException("El empleado no tiene asignada esta habilidad.");
        }

        employee.getSkills().remove(skill);
        employeeRepository.save(employee);

        return mapper.toResponse(employee, skill, "Habilidad eliminada exitosamente");
    }

    /**
     * ✅ Devuelve todas las habilidades de un empleado
     */
    @Override
    public List<EmployeeSkillResponse> findSkillsByEmployee(Long employeeId) {
        Employee employee = employeeRepository.findById(employeeId)
                .orElseThrow(() -> new ResourceNotFoundException("Empleado no encontrado con ID: " + employeeId));

        return employee.getSkills().stream()
                .map(skill -> mapper.toResponse(employee, skill, ""))
                .collect(Collectors.toList());
    }

    /**
     * ✅ Devuelve todos los empleados que tienen una habilidad específica
     */
    @Override
    public List<EmployeeSkillResponse> findEmployeesBySkill(Long skillId) {
        Skill skill = skillRepository.findById(skillId)
                .orElseThrow(() -> new ResourceNotFoundException("Habilidad no encontrada con ID: " + skillId));

        return skill.getEmployees().stream()
                .map(employee -> mapper.toResponse(employee, skill, ""))
                .collect(Collectors.toList());
    }
    /**
     * ✅ Devuelve todas las relaciones empleado-habilidad
     */
    @Override
    public List<EmployeeSkillResponse> getAllEmployeeSkills() {
        return employeeRepository.findAll().stream()
                .flatMap(employee -> employee.getSkills().stream()
                        .map(skill -> mapper.toResponse(employee, skill, "")))
                .collect(Collectors.toList());
    }


}
