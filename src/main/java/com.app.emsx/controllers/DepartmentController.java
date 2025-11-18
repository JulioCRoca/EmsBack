package com.app.emsx.controllers;

import com.app.emsx.dtos.department.DepartmentRequest;
import com.app.emsx.dtos.department.DepartmentResponse;
import com.app.emsx.common.ApiResponse;
import com.app.emsx.services.DepartmentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 🏢 DepartmentController
 * -----------------------------------------------------
 * CRUD completo con respuestas estandarizadas.
 */
@RestController
@RequestMapping("/api/departments")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class DepartmentController {

    private final DepartmentService service;

    @PostMapping
    public ResponseEntity<ApiResponse<DepartmentResponse>> create(@Valid @RequestBody DepartmentRequest request) {
        DepartmentResponse created = service.create(request);
        return ResponseEntity.ok(ApiResponse.ok("Departamento creado correctamente", created));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<DepartmentResponse>> update(
            @PathVariable Long id, @Valid @RequestBody DepartmentRequest request) {
        DepartmentResponse updated = service.update(id, request);
        return ResponseEntity.ok(ApiResponse.ok("Departamento actualizado correctamente", updated));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<DepartmentResponse>>> findAll() {
        return ResponseEntity.ok(ApiResponse.ok("Lista de departamentos", service.findAll()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<DepartmentResponse>> findById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok("Departamento encontrado", service.findById(id)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.ok(ApiResponse.ok("Departamento eliminado correctamente", null));
    }
}
