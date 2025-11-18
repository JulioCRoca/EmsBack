package com.app.emsx.dtos.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * AuthenticationResponse
 * -----------------------------------------------------
 * ✔ DTO de respuesta para login y registro
 * ✔ Devuelve token JWT y datos del usuario autenticado
 * ✔ Compatible con el frontend (React/Next.js)
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {

    /**
     * Token JWT generado tras autenticación
     */
    private String token;
    /**
     * Refresh token para renovar el access token
     */
    private String refreshToken;

    /**
     * ID del usuario (opcional para frontend)
     */
    private Long userId;

    /**
     * Correo electrónico del usuario
     */
    private String email;

    /**
     * Nombre del usuario
     */
    private String firstname;

    /**
     * Apellido del usuario
     */
    private String lastname;

    /**
     * Rol del usuario (ejemplo: ROLE_ADMIN, ROLE_USER)
     */
    private String role;
}
