package com.app.emsx.mappers;

import com.app.emsx.dtos.skill.SkillRequest;
import com.app.emsx.dtos.skill.SkillResponse;
import com.app.emsx.entities.Skill;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface SkillMapper {

    default Skill toEntity(SkillRequest dto) {
        if (dto == null) return null;
        Skill entity = new Skill();
        entity.setName(dto.getName());
        entity.setDescription(dto.getDescription());
        return entity;
    }

    default SkillResponse toResponse(Skill entity) {
        if (entity == null) return null;
        SkillResponse dto = new SkillResponse();
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

    default List<SkillResponse> toResponseList(List<Skill> entities) {
        if (entities == null) return new ArrayList<>();
        return entities.stream().map(this::toResponse).collect(Collectors.toList());
    }

    default void updateEntityFromRequest(SkillRequest dto, Skill entity) {
        if (dto == null || entity == null) return;
        if (dto.getName() != null && !dto.getName().isBlank()) entity.setName(dto.getName());
        if (dto.getDescription() != null) entity.setDescription(dto.getDescription());
    }
}
