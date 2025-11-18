package com.app.emsx.controllers;

import com.app.emsx.dtos.skill.SkillRequest;
import com.app.emsx.dtos.skill.SkillResponse;
import com.app.emsx.common.ApiResponse;
import com.app.emsx.services.SkillService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 🧠 SkillController
 * -----------------------------------------------------
 * Control de habilidades con validaciones de negocio.
 */
@RestController
@RequestMapping("/api/skills")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class SkillController {

    private final SkillService service;

    @PostMapping
    public ResponseEntity<ApiResponse<SkillResponse>> create(@Valid @RequestBody SkillRequest request) {
        SkillResponse created = service.create(request);
        return ResponseEntity.ok(ApiResponse.ok("Habilidad creada correctamente", created));
    }

    @PutMapping("/{id}")
    public ResponseEntity<ApiResponse<SkillResponse>> update(
            @PathVariable Long id, @Valid @RequestBody SkillRequest request) {
        SkillResponse updated = service.update(id, request);
        return ResponseEntity.ok(ApiResponse.ok("Habilidad actualizada correctamente", updated));
    }

    @GetMapping
    public ResponseEntity<ApiResponse<List<SkillResponse>>> findAll() {
        return ResponseEntity.ok(ApiResponse.ok("Lista de habilidades", service.findAll()));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<SkillResponse>> findById(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok("Habilidad encontrada", service.findById(id)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<ApiResponse<Void>> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.ok(ApiResponse.ok("Habilidad eliminada correctamente", null));
    }
}
