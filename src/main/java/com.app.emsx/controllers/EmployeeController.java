package com.app.emsx.controllers;

import com.app.emsx.dtos.employee.EmployeeRequest;
import com.app.emsx.dtos.employee.EmployeeResponse;
import com.app.emsx.common.ApiResponse;
import com.app.emsx.services.EmployeeService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 👨‍💼 EmployeeController
 * -----------------------------------------------------
 * CRUD completo + validaciones automáticas.
 */
@RestController
@RequestMapping("/api/employees")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class EmployeeController {

    private final EmployeeService service;

    @PostMapping
    public ResponseEntity<ApiResponse<EmployeeResponse>> create(@Valid @RequestBody EmployeeRequest request) {
        EmployeeResponse created = service.create(request);
        return ResponseEntity.ok(ApiResponse.ok("Empleado creado correctamente", created));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<EmployeeResponse>> update(
            @PathVariable Long id, @Valid @RequestBody EmployeeRequest request) {
        EmployeeResponse updated = service.update(id, request);
        return ResponseEntity.ok(ApiResponse.ok("Empleado actualizado correctamente", updated));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<EmployeeResponse>>> findAll() {
        return ResponseEntity.ok(ApiResponse.ok("Lista de empleados", service.findAll()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<EmployeeResponse>> findById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok("Empleado encontrado", service.findById(id)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.ok(ApiResponse.ok("Empleado eliminado correctamente", null));
    }
}
