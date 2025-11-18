package com.app.emsx.common;

import lombok.*;
import java.time.LocalDateTime;

/**
 * ApiResponse<T>
 * -----------------------------------------------------
 * ✅ Estandariza todas las respuestas JSON del sistema
 * ✅ Incluye metadatos útiles para auditoría y depuración
 * ✅ Usado en controladores y servicios
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiResponse<T> {
    private boolean success;        // true = OK, false = error
    private String message;         // descripción breve
    private T data;                 // objeto o lista de datos
    private LocalDateTime timestamp;

    public static <T> ApiResponse<T> ok(String message, T data) {
        return ApiResponse.<T>builder()
                .success(true)
                .message(message)
                .data(data)
                .timestamp(LocalDateTime.now())
                .build();
    }

    public static <T> ApiResponse<T> fail(String message) {
        return ApiResponse.<T>builder()
                .success(false)
                .message(message)
                .timestamp(LocalDateTime.now())
                .build();
    }
}
