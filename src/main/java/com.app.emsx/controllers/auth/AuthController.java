package com.app.emsx.controllers.auth;

import com.app.emsx.dtos.auth.AuthenticationRequest;
import com.app.emsx.dtos.auth.AuthenticationResponse;
import com.app.emsx.dtos.auth.RefreshTokenRequest;
import com.app.emsx.dtos.auth.RegisterRequest;
import com.app.emsx.entities.User;
import com.app.emsx.repositories.UserRepository;
import com.app.emsx.serviceimpls.AuthServiceImpl;
import com.app.emsx.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

/**
 * AuthController
 * -----------------------------------------------------
 * ✔ /register → registra un nuevo usuario
 * ✔ /login → devuelve token y datos del usuario
 * ✔ /me → devuelve el usuario autenticado (JWT requerido)
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "*") // ✅ Permitir peticiones desde el frontend (localhost:3000)
public class AuthController {

    private final AuthService authService;
    private final UserRepository userRepository;

    /**
     * ✅ Registro de nuevo usuario
     * Endpoint: POST /api/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * ✅ Login de usuario existente
     * Endpoint: POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    /**
     * ✅ Devuelve los datos del usuario autenticado según el token JWT
     * Endpoint: GET /api/auth/me
     */
    @GetMapping("/me")
    public ResponseEntity<?> getAuthenticatedUser() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (authentication == null || authentication.getName() == null) {
                return ResponseEntity.status(401).body("Usuario no autenticado");
            }

            String email = authentication.getName();
            User user = userRepository.findByEmail(email).orElse(null);

            if (user == null) {
                return ResponseEntity.status(404).body("Usuario no encontrado");
            }

            // Ocultamos la contraseña antes de devolver
            user.setPassword(null);
            return ResponseEntity.ok(user);

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                    .body("Error al obtener usuario autenticado: " + e.getMessage());
        }
    }
    /**
     * 🔁 Refresca el access token usando un refresh token válido
     * Endpoint: POST /api/auth/refresh
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody RefreshTokenRequest request) {
        try {
            AuthenticationResponse response = authService.refreshToken(request.getRefreshToken());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("No se pudo refrescar el token: " + e.getMessage());
        }
    }

}
