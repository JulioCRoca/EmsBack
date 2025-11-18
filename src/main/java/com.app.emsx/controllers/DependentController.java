package com.app.emsx.controllers;

import com.app.emsx.common.ApiResponse;
import com.app.emsx.dtos.dependent.DependentRequest;
import com.app.emsx.dtos.dependent.DependentResponse;
import com.app.emsx.services.DependentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/dependents")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class DependentController {

    private final DependentService service;

    @PostMapping
    public ResponseEntity<ApiResponse<DependentResponse>> create(
            @Valid @RequestBody DependentRequest request) {

        DependentResponse created = service.createDependent(request);
        return ResponseEntity.ok(ApiResponse.ok("Dependiente creado correctamente", created));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<?>> findAll() {
        return ResponseEntity.ok(ApiResponse.ok("Lista de dependientes", service.findAll()));
    }

    @GetMapping("/employee/{employeeId}")
    public ResponseEntity<ApiResponse<?>> getByEmployee(@PathVariable Long employeeId) {
        return ResponseEntity.ok(ApiResponse.ok("Dependientes del empleado", service.getDependentsByEmployee(employeeId)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long id) {
        service.deleteDependent(id);
        return ResponseEntity.ok(ApiResponse.ok("Dependiente eliminado correctamente", null));
    }
}
