package com.example.demosecurity.Service;

import com.example.demosecurity.Entity.AppRole;
import com.example.demosecurity.Entity.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewuser (AppUser appUser);
    AppRole addNewRole (AppRole appRole);
    void addRoleToUser(String userName, String rolename);
    AppUser loadUserByUsername(String username);
    List<AppUser> lisUser();
}
