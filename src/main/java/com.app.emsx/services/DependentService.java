package com.app.emsx.services;

import com.app.emsx.dtos.dependent.DependentRequest;
import com.app.emsx.dtos.dependent.DependentResponse;

import java.util.List;

/**
 * 👨‍👩‍👧 DependentService
 * -----------------------------------------------------
 * Define las operaciones de negocio relacionadas con los dependientes.
 * - Separa claramente la lógica de negocio de la capa web.
 * - Retorna DTOs limpios y listos para el frontend.
 */
public interface DependentService {

    /**
     * ✅ Crear un nuevo dependiente asociado a un empleado.
     */
    DependentResponse createDependent(DependentRequest request);

    /**
     * ✅ Obtener todos los dependientes registrados.
     */
    List<DependentResponse> findAll();

    /**
     * ✅ Obtener los dependientes asociados a un empleado específico.
     */
    List<DependentResponse> getDependentsByEmployee(Long employeeId);

    /**
     * ✅ Eliminar un dependiente por su ID.
     */
    void deleteDependent(Long dependentId);
}
