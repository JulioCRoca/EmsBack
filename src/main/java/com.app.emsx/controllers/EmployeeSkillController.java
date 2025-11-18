package com.app.emsx.controllers;

import com.app.emsx.dtos.employeeSkill.EmployeeSkillRequest;
import com.app.emsx.dtos.employeeSkill.EmployeeSkillResponse;
import com.app.emsx.common.ApiResponse; // ✅ asegúrate que la ruta coincida (puede ser .responses)
import com.app.emsx.services.EmployeeSkillService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 🔗 EmployeeSkillController
 * -----------------------------------------------------
 * Gestiona relaciones entre empleados y habilidades (Many-To-Many)
 * con respuestas estandarizadas y validación de negocio.
 */
@RestController
@RequestMapping("/api/employee-skills")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class EmployeeSkillController {

    private final EmployeeSkillService service;

    /**
     * ✅ Asigna una habilidad a un empleado
     */
    @PostMapping("/assign")
    public ResponseEntity<ApiResponse<EmployeeSkillResponse>> assignSkill(
            @Valid @RequestBody EmployeeSkillRequest request) {

        EmployeeSkillResponse response = service.assignSkill(request);
        return ResponseEntity.ok(ApiResponse.ok("Habilidad asignada correctamente", response));
    }

    /**
     * ✅ Elimina una habilidad de un empleado
     */
    @DeleteMapping("/remove")
    public ResponseEntity<ApiResponse<EmployeeSkillResponse>> removeSkill(
            @Valid @RequestBody EmployeeSkillRequest request) {

        EmployeeSkillResponse response = service.removeSkill(request);
        return ResponseEntity.ok(ApiResponse.ok("Habilidad eliminada correctamente", response));
    }

    /**
     * ✅ Obtiene todas las habilidades de un empleado
     */
    @GetMapping("/employee/{employeeId}")
    public ResponseEntity<ApiResponse<List<EmployeeSkillResponse>>> findSkillsByEmployee(
            @PathVariable Long employeeId) {

        List<EmployeeSkillResponse> list = service.findSkillsByEmployee(employeeId);
        return ResponseEntity.ok(ApiResponse.ok("Habilidades del empleado", list));
    }

    /**
     * ✅ Obtiene todos los empleados con una habilidad dada
     */
    @GetMapping("/skill/{skillId}")
    public ResponseEntity<ApiResponse<List<EmployeeSkillResponse>>> findEmployeesBySkill(
            @PathVariable Long skillId) {

        List<EmployeeSkillResponse> list = service.findEmployeesBySkill(skillId);
        return ResponseEntity.ok(ApiResponse.ok("Empleados con esta habilidad", list));
    }
    @GetMapping
    public ResponseEntity<ApiResponse<List<EmployeeSkillResponse>>> getAllEmployeeSkills() {
        return ResponseEntity.ok(ApiResponse.ok("Lista de empleados-skills", service.getAllEmployeeSkills()));
    }
}
