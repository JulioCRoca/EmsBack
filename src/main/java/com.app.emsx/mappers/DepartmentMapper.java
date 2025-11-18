package com.app.emsx.mappers;

import com.app.emsx.dtos.department.DepartmentRequest;
import com.app.emsx.dtos.department.DepartmentResponse;
import com.app.emsx.entities.Department;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface DepartmentMapper {

    // ✅ DTO → Entity
    default Department toEntity(DepartmentRequest dto) {
        if (dto == null) return null;
        Department entity = new Department();
        entity.setName(dto.getName());
        entity.setDescription(dto.getDescription());
        return entity;
    }

    // ✅ Entity → DTO
    default DepartmentResponse toResponse(Department entity) {
        if (entity == null) return null;
        DepartmentResponse dto = new DepartmentResponse();
        dto.setId(entity.getId());
        dto.setName(entity.getName());
        dto.setDescription(entity.getDescription());
        if (entity.getEmployees() != null) {
            dto.setEmployeeNames(
                    entity.getEmployees()
                            .stream()
                            .map(emp -> emp.getFirstName() + " " + emp.getLastName())
                            .collect(Collectors.toList())
            );
        } else {
            dto.setEmployeeNames(new ArrayList<>());
        }
        return dto;
    }

    // ✅ List conversion
    default List<DepartmentResponse> toResponseList(List<Department> entities) {
        if (entities == null) return new ArrayList<>();
        return entities.stream().map(this::toResponse).collect(Collectors.toList());
    }

    // ✅ Actualización parcial
    default void updateEntityFromRequest(DepartmentRequest dto, Department entity) {
        if (dto == null || entity == null) return;
        if (dto.getName() != null && !dto.getName().isBlank()) entity.setName(dto.getName());
        if (dto.getDescription() != null) entity.setDescription(dto.getDescription());
    }
}
