package com.secure.notes.service;

import com.secure.notes.dto.UserDto;
import com.secure.notes.model.User;

import java.util.List;

public interface UserService {
    void updateUserRole(Long userId,String roleName);
    List<User> getAllUser();
    UserDto getUserById(Long id);
    User findByUsername(String username);

}
