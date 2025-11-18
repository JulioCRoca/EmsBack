package com.app.emsx.controllers;

import com.app.emsx.repositories.EmployeeRepository;
import com.app.emsx.repositories.DepartmentRepository;
import com.app.emsx.repositories.SkillRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // ✅ Permitir acceso desde el frontend (localhost:3000)
public class DashboardController {

    private final EmployeeRepository employeeRepository;
    private final DepartmentRepository departmentRepository;
    private final SkillRepository skillRepository;

    @GetMapping("/stats")
    public ResponseEntity<?> getDashboardStats() {
        try {
            long employees = employeeRepository.count();
            long departments = departmentRepository.count();
            long skills = skillRepository.count();

            // Agrupar empleados por departamento
            List<Object[]> deptStats = employeeRepository.countEmployeesByDepartment();

            // Crear estructura para el gráfico de barras
            List<Map<String, Object>> employeesPerDept = new ArrayList<>();
            for (Object[] row : deptStats) {
                employeesPerDept.add(Map.of(
                        "name", row[0], // Nombre del departamento
                        "value", ((Number) row[1]).intValue()
                ));
            }

            Map<String, Object> response = new HashMap<>();
            response.put("employees", employees);
            response.put("departments", departments);
            response.put("skills", skills);
            response.put("employeesPerDept", employeesPerDept);

            // Simular datos de tendencias (podrás reemplazar por fechas reales)
            List<Map<String, Object>> trendData = List.of(
                    Map.of("month", "Jan", "newEmployees", 5, "resignations", 2),
                    Map.of("month", "Feb", "newEmployees", 3, "resignations", 1),
                    Map.of("month", "Mar", "newEmployees", 6, "resignations", 3),
                    Map.of("month", "Apr", "newEmployees", 4, "resignations", 2),
                    Map.of("month", "May", "newEmployees", 8, "resignations", 1)
            );

            response.put("trendData", trendData);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body(Map.of("error", "Error loading dashboard: " + e.getMessage()));
        }
    }
}
