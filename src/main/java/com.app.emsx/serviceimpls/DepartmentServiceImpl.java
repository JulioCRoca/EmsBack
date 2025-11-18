package com.app.emsx.serviceimpls;

import com.app.emsx.dtos.department.DepartmentRequest;
import com.app.emsx.dtos.department.DepartmentResponse;
import com.app.emsx.entities.Department;
import com.app.emsx.exceptions.BusinessRuleException;
import com.app.emsx.exceptions.ResourceNotFoundException;
import com.app.emsx.mappers.DepartmentMapper;
import com.app.emsx.repositories.DepartmentRepository;
import com.app.emsx.services.DepartmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 🧠 DepartmentServiceImpl
 * -----------------------------------------------------
 * Servicio empresarial para gestión de departamentos.
 * Aplica reglas de negocio, validaciones y conversión DTO ↔ Entity.
 */
@Service
@RequiredArgsConstructor
public class DepartmentServiceImpl implements DepartmentService {

    private final DepartmentRepository repository;
    private final DepartmentMapper mapper;

    @Override
    public DepartmentResponse create(DepartmentRequest request) {
        if (repository.existsByName(request.getName())) {
            throw new BusinessRuleException("Ya existe un departamento con el nombre: " + request.getName());
        }

        Department entity = mapper.toEntity(request);
        return mapper.toResponse(repository.save(entity));
    }

    @Override
    public DepartmentResponse update(Long id, DepartmentRequest request) {
        Department department = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Departamento no encontrado con ID: " + id));

        if (!department.getName().equals(request.getName()) &&
                repository.existsByName(request.getName())) {
            throw new BusinessRuleException("Ya existe otro departamento con el nombre: " + request.getName());
        }

        mapper.updateEntityFromRequest(request, department);
        return mapper.toResponse(repository.save(department));
    }

    @Override
    public List<DepartmentResponse> findAll() {
        return repository.findAll()
                .stream()
                .map(mapper::toResponse)
                .collect(Collectors.toList());
    }

    @Override
    public DepartmentResponse findById(Long id) {
        Department department = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Departamento no encontrado con ID: " + id));
        return mapper.toResponse(department);
    }

    @Override
    public void delete(Long id) {
        Department department = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Departamento no encontrado con ID: " + id));
        repository.delete(department);
    }
}
