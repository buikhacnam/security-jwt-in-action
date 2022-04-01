package com.buinam.userservice;

import com.buinam.userservice.model.AppUser;
import com.buinam.userservice.model.Role;
import com.buinam.userservice.service.AppUserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class UserServiceApplication {

	public static void main(String[] args) {

		SpringApplication.run(UserServiceApplication.class, args);
		System.out.println("HI MOM!");
	}

	@Bean
	BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

//	@Bean
//	CommandLineRunner runner(AppUserService appUserService) {
//		return (args) -> {
//			System.out.println("Run from commandline!");
//
//			appUserService.saveRole(new Role(null, "ROLE_ADMIN"));
//			appUserService.saveRole(new Role(null, "ROLE_USER"));
//			appUserService.saveRole(new Role(null, "ROLE_MANAGER"));
//			appUserService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
//
//
//			appUserService.saveUser(new AppUser(null, "Didier Drogba", "drogba", "1234", new ArrayList<>()));
//			appUserService.saveUser(new AppUser(null, "Frank Lampard", "lampard", "1234", new ArrayList<>()));
//			appUserService.saveUser(new AppUser(null, "John Terry", "terry", "1234", new ArrayList<>()));
//			appUserService.saveUser(new AppUser(null, "Jose Mourinho", "mourinho", "1234", new ArrayList<>()));
//
//			appUserService.addRoleToUser("drogba", "ROLE_ADMIN");
//			appUserService.addRoleToUser("drogba", "ROLE_USER");
//			appUserService.addRoleToUser("lampard", "ROLE_USER");
//			appUserService.addRoleToUser("terry", "ROLE_MANAGER");
//			appUserService.addRoleToUser("terry", "ROLE_USER");
//			appUserService.addRoleToUser("mourinho", "ROLE_SUPER_ADMIN");
//
//		};
//	}

}
