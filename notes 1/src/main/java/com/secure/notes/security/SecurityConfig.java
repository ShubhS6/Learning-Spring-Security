package com.secure.notes.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception{
        //http.authorizeHttpRequests(request-> request.anyRequest().authenticated());
        http.authorizeHttpRequests(request-> request.requestMatchers("/hello").permitAll());
        http.formLogin(Customizer.withDefaults());
       http.httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
