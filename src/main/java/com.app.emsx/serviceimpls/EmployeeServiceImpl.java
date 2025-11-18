package com.app.emsx.serviceimpls;

import com.app.emsx.dtos.employee.EmployeeRequest;
import com.app.emsx.dtos.employee.EmployeeResponse;
import com.app.emsx.entities.Department;
import com.app.emsx.entities.Employee;
import com.app.emsx.exceptions.BusinessRuleException;
import com.app.emsx.exceptions.ResourceNotFoundException;
import com.app.emsx.mappers.EmployeeMapper;
import com.app.emsx.repositories.DepartmentRepository;
import com.app.emsx.repositories.EmployeeRepository;
import com.app.emsx.services.EmployeeService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 👔 EmployeeServiceImpl
 * -----------------------------------------------------
 * Servicio principal para gestión de empleados.
 * ✅ Aplica reglas de negocio, validaciones y conversiones DTO ↔ Entity.
 * ✅ Garantiza integridad referencial con Department y Dependents.
 */
@Service
@RequiredArgsConstructor
public class EmployeeServiceImpl implements EmployeeService {

    private final EmployeeRepository repository;
    private final DepartmentRepository departmentRepository;
    private final EmployeeMapper mapper;

    /**
     * ✅ Crear nuevo empleado
     * - Verifica que el correo no esté duplicado.
     * - Asigna correctamente el departamento.
     */
    @Override
    public EmployeeResponse create(EmployeeRequest request) {
        // Verificar duplicado de email
        if (repository.existsByEmail(request.getEmail())) {
            throw new BusinessRuleException("Ya existe un empleado con el email: " + request.getEmail());
        }

        // Verificar existencia del departamento
        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new ResourceNotFoundException("Departamento no encontrado con ID: " + request.getDepartmentId()));

        // Mapear DTO → Entity
        Employee employee = mapper.toEntity(request);
        employee.setDepartment(department);

        // Guardar y retornar
        return mapper.toResponse(repository.save(employee));
    }

    /**
     * ✅ Actualizar empleado existente
     * - Verifica duplicados de email.
     * - Asegura que el departamento exista.
     */
    @Override
    public EmployeeResponse update(Long id, EmployeeRequest request) {
        Employee employee = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Empleado no encontrado con ID: " + id));

        // Validar email duplicado
        if (!employee.getEmail().equals(request.getEmail()) &&
                repository.existsByEmail(request.getEmail())) {
            throw new BusinessRuleException("Ya existe otro empleado con el email: " + request.getEmail());
        }

        // Validar y asignar departamento
        Department department = departmentRepository.findById(request.getDepartmentId())
                .orElseThrow(() -> new ResourceNotFoundException("Departamento no encontrado con ID: " + request.getDepartmentId()));

        mapper.updateEntityFromRequest(request, employee);
        employee.setDepartment(department);

        return mapper.toResponse(repository.save(employee));
    }

    /**
     * ✅ Obtener todos los empleados
     */
    @Override
    public List<EmployeeResponse> findAll() {
        return repository.findAll()
                .stream()
                .map(mapper::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * ✅ Buscar empleado por ID
     */
    @Override
    public EmployeeResponse findById(Long id) {
        Employee employee = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Empleado no encontrado con ID: " + id));
        return mapper.toResponse(employee);
    }

    /**
     * ✅ Eliminar empleado por ID
     * - Si tiene dependientes, lanzar excepción de negocio.
     */
    @Override
    public void delete(Long id) {
        Employee employee = repository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Empleado no encontrado con ID: " + id));

        if (employee.getDependents() != null && !employee.getDependents().isEmpty()) {
            throw new BusinessRuleException("No se puede eliminar un empleado con dependientes asociados");
        }

        repository.delete(employee);
    }
}
