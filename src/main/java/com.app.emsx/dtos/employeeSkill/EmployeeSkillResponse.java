package com.app.emsx.dtos.employeeSkill;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmployeeSkillResponse {
    private Long employeeId;
    private String employeeFullName;
    private Long skillId;
    private String skillName;
    private String message; // opcional: indica el resultado de la acción
}
