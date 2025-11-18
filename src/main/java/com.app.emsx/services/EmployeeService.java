package com.app.emsx.services;

import com.app.emsx.dtos.employee.EmployeeRequest;
import com.app.emsx.dtos.employee.EmployeeResponse;

import java.util.List;

public interface EmployeeService {
    EmployeeResponse create(EmployeeRequest request);
    EmployeeResponse update(Long id, EmployeeRequest request);
    void delete(Long id);
    EmployeeResponse findById(Long id);
    List<EmployeeResponse> findAll();
}
