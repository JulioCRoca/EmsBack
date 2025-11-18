package com.app.emsx.mappers;

import com.app.emsx.dtos.dependent.DependentRequest;
import com.app.emsx.dtos.dependent.DependentResponse;
import com.app.emsx.entities.Dependent;
import org.mapstruct.Mapper;
import org.mapstruct.ReportingPolicy;

@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface DependentMapper {

    Dependent toEntity(DependentRequest dto);

    DependentResponse toResponse(Dependent entity);
}
