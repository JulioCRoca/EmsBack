package com.app.emsx.dtos.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AuthenticationRequest
 * -----------------------------------------------------
 * ✔ DTO para recibir datos de inicio de sesión
 * ✔ Compatible con el frontend (React/Next.js)
 * ✔ Usado en /api/auth/login
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationRequest {

    /**
     * Correo electrónico del usuario
     */
    private String email;

    /**
     * Contraseña del usuario
     */
    private String password;
}
