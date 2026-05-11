package com.secure.notes.service;

import com.secure.notes.dto.UserDto;
import com.secure.notes.model.Role;
import com.secure.notes.model.User;

import java.util.List;

public interface UserService {
    void updateUserRole(Long userId,String roleName);
    List<User> getAllUser();
    UserDto getUserById(Long id);
    User findByUsername(String username);

    void updateAccountLockStatus(Long userId, boolean lock);

    List<Role> getAllRoles();

    void updateAccountExpiryStatus(Long userId, boolean expire);

    void updateAccountEnabledStatus(Long userId, boolean enabled);

    void updateCredentialsExpiryStatus(Long userId, boolean expire);

    void updatePassword(Long userId, String password);
}
