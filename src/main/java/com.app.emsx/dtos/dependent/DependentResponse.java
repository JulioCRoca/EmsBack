package com.app.emsx.dtos.dependent;

import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DependentResponse {
    private Long id;
    private String name;
    private String relationship;
    private String phone;
}
