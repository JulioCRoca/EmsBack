package com.app.emsx.security;

import com.app.emsx.entities.User;
import com.app.emsx.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * CustomUserDetailsService
 * -----------------------------------------------------
 * ✔ Carga los detalles del usuario desde la base de datos
 * ✔ Usa el email como identificador (username)
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // 🔍 Buscar por email (no por username)
        return userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("❌ Usuario no encontrado: " + username));
    }
}
