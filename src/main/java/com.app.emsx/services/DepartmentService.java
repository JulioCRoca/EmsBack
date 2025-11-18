package com.app.emsx.services;

import com.app.emsx.dtos.department.DepartmentRequest;
import com.app.emsx.dtos.department.DepartmentResponse;

import java.util.List;

public interface DepartmentService {
    DepartmentResponse create(DepartmentRequest request);
    DepartmentResponse update(Long id, DepartmentRequest request);
    void delete(Long id);
    DepartmentResponse findById(Long id);
    List<DepartmentResponse> findAll();
}
