package com.app.emsx.dtos.employee;

import lombok.*;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmployeeSkillUpdateRequest {
    private Set<Long> skillIds; // IDs de habilidades seleccionadas
}
