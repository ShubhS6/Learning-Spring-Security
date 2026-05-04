package com.secure.notes.securityFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;


//@Component
public class CustomLoggingFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        System.out.println("Custom Logging Filter request-> "+request.getRequestURI());
        filterChain.doFilter(request,response);
        System.out.println("Custom Logging Filter response-> "+response.getStatus());
    }
}
