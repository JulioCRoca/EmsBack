package com.app.emsx.exceptions;

/**
 * 🚫 ResourceNotFoundException
 * ---------------------------------------------------------
 * ✅ Se lanza cuando un recurso solicitado no existe en la base de datos.
 * ✅ Centraliza la comunicación de errores 404 (Not Found).
 * ✅ Compatible con GlobalExceptionHandler para devolver respuestas JSON uniformes.
 *
 * Ejemplo de uso:
 * ---------------------------------------------------------
 * employeeRepository.findById(id)
 *      .orElseThrow(() -> new ResourceNotFoundException("Empleado no encontrado"));
 *
 * Resultado JSON automático:
 * {
 *   "success": false,
 *   "message": "Empleado no encontrado",
 *   "timestamp": "2025-10-30T10:42:15"
 * }
 */
public class ResourceNotFoundException extends RuntimeException {

    /**
     * Constructor con mensaje personalizado.
     * Ejemplo: new ResourceNotFoundException("Departamento no encontrado");
     */
    public ResourceNotFoundException(String message) {
        super(message);
    }

    /**
     * Constructor extendido (opcional) con causa original.
     * Ejemplo: new ResourceNotFoundException("Error al buscar empleado", e);
     */
    public ResourceNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
