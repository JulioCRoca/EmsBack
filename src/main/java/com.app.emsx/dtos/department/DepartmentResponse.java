package com.app.emsx.dtos.department;

import lombok.*;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DepartmentResponse {

    private Long id;
    private String name;
    private String description;
    private List<String> employeeNames; // ✅ Nombres de empleados asociados
}
