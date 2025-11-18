package com.app.emsx.dtos.department;

import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DepartmentRequest {

    @NotBlank(message = "El nombre del departamento es obligatorio")
    private String name;

    private String description;
}
