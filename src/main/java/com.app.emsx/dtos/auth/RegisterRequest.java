package com.app.emsx.dtos.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * RegisterRequest
 * -----------------------------------------------------
 * ✔ DTO para registro de nuevos usuarios
 * ✔ Compatible con el frontend (React/Next.js)
 * ✔ Usado en /api/auth/register
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    /**
     * Nombre del usuario
     */
    private String firstname;

    /**
     * Apellido del usuario
     */
    private String lastname;

    /**
     * Correo electrónico único del usuario
     */
    private String email;

    /**
     * Contraseña del usuario
     */
    private String password;
}
