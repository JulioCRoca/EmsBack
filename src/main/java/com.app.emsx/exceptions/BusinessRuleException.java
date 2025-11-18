package com.app.emsx.exceptions;

/**
 * ⚖️ BusinessRuleException
 * ---------------------------------------------------------
 * Excepción personalizada para violaciones de reglas de negocio.
 *
 * Se lanza cuando una acción o dato incumple una regla lógica de la aplicación,
 * por ejemplo:
 *   - Intentar eliminar un empleado con dependientes activos
 *   - Asignar un skill duplicado
 *   - Crear un departamento con nombre ya existente
 *
 * Es capturada por el GlobalExceptionHandler y devuelve HTTP 409 (Conflict)
 */
public class BusinessRuleException extends RuntimeException {

    public BusinessRuleException(String message) {
        super(message);
    }

    public BusinessRuleException(String message, Throwable cause) {
        super(message, cause);
    }
}
