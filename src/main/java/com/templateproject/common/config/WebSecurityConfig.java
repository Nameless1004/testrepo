package com.templateproject.common.config;

import com.templateproject.security.SecurityFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity // Spring Security 지원을 가능하게 함
@EnableMethodSecurity(securedEnabled  = true) // @Secured 사용가능하게
public class WebSecurityConfig {

    private final SecurityFilter securityFilter;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // SessionManagementFilter, SecurityContextPersistenceFilter
            )
            .addFilterBefore(securityFilter, SecurityContextHolderAwareRequestFilter.class)
            .formLogin(AbstractHttpConfigurer::disable) // UsernamePasswordAuthenticationFilter, DefaultLoginPageGeneratingFilter 비활성화
            .anonymous(AbstractHttpConfigurer::disable) // AnonymousAuthenticationFilter 비활성화
            .httpBasic(AbstractHttpConfigurer::disable) // BasicAuthenticationFilter 비활성화
            .logout(AbstractHttpConfigurer::disable) // LogoutFilter 비활성화
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/signup", "/auth/login", "/auth/reissue").permitAll()
                .requestMatchers("/user/**").permitAll()
                .requestMatchers("/auth/logout").authenticated()
                .anyRequest().authenticated()
            );
        http.formLogin((x)->x.loginPage("/user/login"));
        http.cors(c -> {
            c.configurationSource(corsConfigurationSource);});

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
