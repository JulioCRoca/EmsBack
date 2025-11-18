package com.app.emsx.serviceimpls;

import com.app.emsx.dtos.dependent.DependentRequest;
import com.app.emsx.dtos.dependent.DependentResponse;
import com.app.emsx.entities.Dependent;
import com.app.emsx.entities.Employee;
import com.app.emsx.exceptions.BusinessRuleException;
import com.app.emsx.exceptions.ResourceNotFoundException;
import com.app.emsx.mappers.DependentMapper;
import com.app.emsx.repositories.DependentRepository;
import com.app.emsx.repositories.EmployeeRepository;
import com.app.emsx.services.DependentService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

/**
 * 👨‍👩‍👧 DependentServiceImpl
 * -----------------------------------------------------
 * Implementa la lógica de negocio de dependientes.
 * - Valida existencia de empleado antes de asociar.
 * - Evita duplicados por nombre.
 * - Aplica buenas prácticas de servicio limpio.
 */
@Service
@RequiredArgsConstructor
@Transactional
public class DependentServiceImpl implements DependentService {

    private final DependentRepository dependentRepository;
    private final EmployeeRepository employeeRepository;
    private final DependentMapper mapper;

    /**
     * ✅ Crear un nuevo dependiente asociado a un empleado
     */
    @Override
    public DependentResponse createDependent(DependentRequest request) {
        // Verificar existencia del empleado
        Employee employee = employeeRepository.findById(request.getEmployeeId())
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Empleado no encontrado con ID: " + request.getEmployeeId()
                ));

        // Evitar duplicados
        boolean exists = dependentRepository.existsByNameAndEmployee_Id(
                request.getName(),
                employee.getId()
        );
        if (exists) {
            throw new BusinessRuleException("Ya existe un dependiente con ese nombre para este empleado.");
        }

        // Crear dependiente
        Dependent dependent = mapper.toEntity(request);
        dependentRepository.save(dependent);

        return mapper.toResponse(dependent);
    }

    /**
     * ✅ Obtener todos los dependientes registrados
     */
    @Override
    public List<DependentResponse> findAll() {
        return dependentRepository.findAll()
                .stream()
                .map(mapper::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * ✅ Obtener dependientes por empleado
     */
    @Override
    public List<DependentResponse> getDependentsByEmployee(Long employeeId) {
        if (!employeeRepository.existsById(employeeId)) {
            throw new ResourceNotFoundException("Empleado no encontrado con ID: " + employeeId);
        }

        return dependentRepository.findByEmployee_Id(employeeId)
                .stream()
                .map(mapper::toResponse)
                .collect(Collectors.toList());
    }

    /**
     * ✅ Eliminar dependiente por ID
     */
    @Override
    public void deleteDependent(Long dependentId) {
        Dependent dependent = dependentRepository.findById(dependentId)
                .orElseThrow(() -> new ResourceNotFoundException(
                        "Dependiente no encontrado con ID: " + dependentId
                ));
        dependentRepository.delete(dependent);
    }
}
