package com.buinam.userservice.service;

import com.buinam.userservice.controller.AppUserController;
import com.buinam.userservice.model.AppUser;
import com.buinam.userservice.model.Role;

import java.util.List;

public interface AppUserService {
    AppUser saveUser(AppUser user);
    Role saveRole(Role role);
    void addRoleToUser(String userName, String roleName);
    AppUser getUser(String userName);
    List<AppUser> getUsers();
}
