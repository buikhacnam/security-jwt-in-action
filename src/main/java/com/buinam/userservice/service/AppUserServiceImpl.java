package com.buinam.userservice.service;

import com.buinam.userservice.model.AppUser;
import com.buinam.userservice.model.Role;
import com.buinam.userservice.repository.AppUserRepository;
import com.buinam.userservice.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
@Transactional
@Slf4j
@RequiredArgsConstructor // this means we can @Autowire all the fields in the constructor
public class AppUserServiceImpl implements AppUserService, UserDetailsService {

//    @Autowired
    private final AppUserRepository appUserRepository;

//    @Autowired
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final PasswordEncoder passwordEncoder;
    @Override //UserDetailsService
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser user = appUserRepository.findByUsername(username);

        if (user == null) {
            String errorMessage = "User not found with username: " + username;
            log.error(errorMessage);
            throw new UsernameNotFoundException(errorMessage);
        } else {
            log.info("User found: {}", user);
        }


        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>(user.getRoles().size());
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        log.info("User authorities: {}", authorities); //User authorities: [ROLE_USER, ROLE_ADMIN]
        return new User(user.getUsername(), user.getPassword(), authorities);
    }

    @Override
    public AppUser saveUser(AppUser user) {
        log.info("Saving user: {}", user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return appUserRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving role: {}", role);
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String userName, String roleName) {
        log.info("Adding role: {} to user: {}", roleName, userName);
        AppUser user = appUserRepository.findByUsername(userName);
        Role role = roleRepository.findByName(roleName);
        // since we use @Transactional, we don't need to call save()
        user.getRoles().add(role);
    }

    @Override
    public AppUser getUser(String userName) {
        log.info("Getting user: {}", userName);
        return appUserRepository.findByUsername(userName);
    }

    @Override
    public List<AppUser> getUsers() {
        log.info("Getting all users");
        return appUserRepository.findAll();
    }

}
