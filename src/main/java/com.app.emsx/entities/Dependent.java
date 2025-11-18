package com.app.emsx.entities;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "dependents")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Dependent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    // 👇 Esta es la relación correcta que Spring JPA necesita
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "employee_id", nullable = false)
    private Employee employee;

    // (opcional) otros campos
    // private String relationship;
}
