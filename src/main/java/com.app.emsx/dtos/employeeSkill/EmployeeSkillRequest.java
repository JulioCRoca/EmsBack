package com.app.emsx.dtos.employeeSkill;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmployeeSkillRequest {
    private Long employeeId;
    private Long skillId;
}
