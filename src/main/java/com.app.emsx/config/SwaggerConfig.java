package com.app.emsx.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.*;
import io.swagger.v3.oas.models.security.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * SwaggerConfig
 * -----------------------------------------------------
 * ✔ Habilita documentación interactiva de la API con Swagger UI (OpenAPI 3)
 * ✔ Añade soporte para autenticación JWT tipo Bearer
 * ✔ Permite probar /api/auth/login y /api/auth/register directamente
 * ✔ URL de acceso: http://localhost:8080/swagger-ui/index.html
 */
@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("EMSX API - Employee Management System")
                        .version("1.0.0")
                        .description("API REST segura con JWT para gestión de empleados y departamentos."))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")))
                .addSecurityItem(
                        new SecurityRequirement().addList("bearerAuth", List.of("read", "write"))
                );
    }
}
