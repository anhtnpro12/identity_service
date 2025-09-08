package com.anhtrinhnam02.identity_service.mapper;

import com.anhtrinhnam02.identity_service.dto.request.RoleRequest;
import com.anhtrinhnam02.identity_service.dto.response.RoleResponse;
import com.anhtrinhnam02.identity_service.entity.Role;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface RoleMapper {
    @Mapping(target = "permissions", ignore = true)
    Role toRole(RoleRequest request);
    RoleResponse toRoleResponse(Role permission);
}
