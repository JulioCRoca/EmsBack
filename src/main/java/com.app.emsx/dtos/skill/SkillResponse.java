package com.app.emsx.dtos.skill;

import lombok.*;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SkillResponse {

    private Long id;
    private String name;
    private String description;
    private List<String> employeeNames; // ✅ Empleados que poseen esta habilidad
}
