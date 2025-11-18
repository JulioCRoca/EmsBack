package com.app.emsx.entities;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

import java.util.HashSet;
import java.util.Set;

/**
 * Skill Entity
 * -----------------------------------------------------
 * ✔ Representa una habilidad o competencia.
 * ✔ Relación ManyToMany con Employee.
 */
@Entity
@Table(name = "skills")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Skill {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "El nombre de la habilidad es obligatorio.")
    @Size(max = 100, message = "El nombre no puede superar los 100 caracteres.")
    @Column(nullable = false, unique = true)
    private String name;

    @Size(max = 255)
    private String description;

    // 🔁 Relación bidireccional con Employee (lado inverso)
    @ManyToMany(mappedBy = "skills", fetch = FetchType.LAZY)
    private Set<Employee> employees = new HashSet<>();
}
