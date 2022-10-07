package com.hoangit3.oauth2server.repository;

import com.hoangit3.oauth2server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;


public interface UserRepository extends JpaRepository<User,Integer> {

    Optional<User> findByUsername(String name);

	boolean existsByUsername(String name);

}
