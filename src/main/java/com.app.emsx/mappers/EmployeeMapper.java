package com.app.emsx.mappers;

import com.app.emsx.dtos.employee.EmployeeRequest;
import com.app.emsx.dtos.employee.EmployeeResponse;
import com.app.emsx.entities.Employee;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface EmployeeMapper {

    default Employee toEntity(EmployeeRequest dto) {
        if (dto == null) return null;
        Employee entity = new Employee();
        entity.setFirstName(dto.getFirstName());
        entity.setLastName(dto.getLastName());
        entity.setEmail(dto.getEmail());
        entity.setAddress(dto.getAddress());
        entity.setPhone(dto.getPhone());
        return entity;
    }

    default EmployeeResponse toResponse(Employee entity) {
        if (entity == null) return null;
        EmployeeResponse dto = new EmployeeResponse();
        dto.setId(entity.getId());
        dto.setFirstName(entity.getFirstName());
        dto.setLastName(entity.getLastName());
        dto.setEmail(entity.getEmail());
        dto.setAddress(entity.getAddress());
        dto.setPhone(entity.getPhone());
        if (entity.getDepartment() != null) {
            dto.setDepartmentName(entity.getDepartment().getName());
        }
        if (entity.getSkills() != null) {
            dto.setSkillNames(
                    entity.getSkills().stream()
                            .map(skill -> skill.getName())
                            .collect(Collectors.toList())
            );
        } else {
            dto.setSkillNames(new ArrayList<>());
        }
        return dto;
    }

    default List<EmployeeResponse> toResponseList(List<Employee> entities) {
        if (entities == null) return new ArrayList<>();
        return entities.stream().map(this::toResponse).collect(Collectors.toList());
    }

    default void updateEntityFromRequest(EmployeeRequest dto, Employee entity) {
        if (dto == null || entity == null) return;
        if (dto.getFirstName() != null && !dto.getFirstName().isBlank())
            entity.setFirstName(dto.getFirstName());
        if (dto.getLastName() != null && !dto.getLastName().isBlank())
            entity.setLastName(dto.getLastName());
        if (dto.getEmail() != null && !dto.getEmail().isBlank())
            entity.setEmail(dto.getEmail());
        if (dto.getAddress() != null) entity.setAddress(dto.getAddress());
        if (dto.getPhone() != null) entity.setPhone(dto.getPhone());
    }
}
