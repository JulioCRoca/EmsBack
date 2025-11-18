package com.app.emsx.serviceimpls;

import com.app.emsx.dtos.auth.AuthenticationRequest;
import com.app.emsx.dtos.auth.AuthenticationResponse;
import com.app.emsx.dtos.auth.RegisterRequest;
import com.app.emsx.entities.User;
import com.app.emsx.repositories.UserRepository;
import com.app.emsx.security.JwtService;
import com.app.emsx.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * AuthServiceImpl
 * -----------------------------------------------------
 * ✔ Gestiona registro y autenticación de usuarios
 * ✔ Genera tokens JWT válidos con roles incluidos
 * ✔ Retorna la respuesta de autenticación al frontend
 */
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    /**
     * ✅ Registrar un nuevo usuario (modo desarrollo con defaults)
     */
    public AuthenticationResponse register(RegisterRequest request) {
        User user = new User();

        // Evitar errores de null en firstname / lastname
        user.setFirstname(
                request.getFirstname() != null && !request.getFirstname().isBlank()
                        ? request.getFirstname()
                        : "User"
        );
        user.setLastname(
                request.getLastname() != null && !request.getLastname().isBlank()
                        ? request.getLastname()
                        : "Default"
        );

        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("ROLE_ADMIN"); // Temporal para desarrollo

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiry(
                new java.util.Date(System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000)
        );
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .email(user.getEmail())
                .firstname(user.getFirstname())
                .lastname(user.getLastname())
                .role(user.getRole())
                .build();

    }

    /**
     * ✅ Autenticar usuario existente
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("❌ Usuario no encontrado"));

        String jwtToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        user.setRefreshToken(refreshToken);
        user.setRefreshTokenExpiry(
                new java.util.Date(System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000)
        );
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .refreshToken(refreshToken)
                .userId(user.getId())
                .email(user.getEmail())
                .firstname(user.getFirstname())
                .lastname(user.getLastname())
                .role(user.getRole())
                .build();

    }
    @Override
    public AuthenticationResponse refreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new RuntimeException("Refresh token vacío");
        }

        String username;
        try {
            username = jwtService.extractUsername(refreshToken);
        } catch (Exception e) {
            throw new RuntimeException("Refresh token inválido");
        }

        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        // Validar que coincida con el guardado en BD
        if (user.getRefreshToken() == null ||
                !user.getRefreshToken().equals(refreshToken)) {
            throw new RuntimeException("Refresh token no coincide");
        }

        // Validar expiración
        if (user.getRefreshTokenExpiry() == null ||
                user.getRefreshTokenExpiry().before(new java.util.Date())) {
            throw new RuntimeException("Refresh token expirado");
        }

        // Generar nuevos tokens
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        user.setRefreshToken(newRefreshToken);
        user.setRefreshTokenExpiry(
                new java.util.Date(System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000)
        );
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .token(newAccessToken)
                .refreshToken(newRefreshToken)
                .userId(user.getId())
                .email(user.getEmail())
                .firstname(user.getFirstname())
                .lastname(user.getLastname())
                .role(user.getRole())
                .build();
    }

    @Override
    public AuthenticationResponse createAdminUser() {
        return null;
    }
}
