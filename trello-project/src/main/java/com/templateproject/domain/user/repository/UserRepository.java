package com.templateproject.domain.user.repository;

import com.templateproject.domain.user.entitiy.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.username=:username")
    Optional<User> findByUsername(@Param("username") String username);

    @Query("SELECT u FROM User u WHERE u.email=:email")
    Optional<User> findByEmail(@Param("email") String email);

    @Query("SELECT u FROM User u WHERE u.nickname=:nickname")
    Optional<User> findByNickname(@Param("nickname") String nickname);

    boolean existsByNickname(String nickname);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);
}
