package com.app.emsx.dtos.employee;

import lombok.*;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmployeeResponse {

    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String address;
    private String phone;

    private String departmentName; // ✅ Nombre del departamento
    private List<String> skillNames; // ✅ Habilidades del empleado
}
