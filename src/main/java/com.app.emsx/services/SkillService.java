package com.app.emsx.services;

import com.app.emsx.dtos.skill.SkillRequest;
import com.app.emsx.dtos.skill.SkillResponse;

import java.util.List;

public interface SkillService {
    SkillResponse create(SkillRequest request);
    SkillResponse update(Long id, SkillRequest request);
    void delete(Long id);
    SkillResponse findById(Long id);
    List<SkillResponse> findAll();
}
