package com.app.emsx.dtos.dependent;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * 🧾 DependentRequest
 * -----------------------------------------------------
 * DTO para crear o actualizar dependientes.
 * Incluye validaciones y referencia al empleado asociado.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DependentRequest {

    @NotBlank(message = "El nombre del dependiente no puede estar vacío.")
    @Size(max = 100, message = "El nombre no puede superar los 100 caracteres.")
    private String name;

    @NotBlank(message = "El parentesco es obligatorio.")
    @Size(max = 50, message = "El parentesco no puede superar los 50 caracteres.")
    private String relationship;

    @Size(max = 100, message = "El teléfono no puede superar los 100 caracteres.")
    private String phone;

    @NotNull(message = "Debe especificar el ID del empleado.")
    private Long employeeId; // ✅ Este campo permite asociar el dependiente a un empleado
}
