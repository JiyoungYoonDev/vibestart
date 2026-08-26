package com.auth.auth_service.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth.auth_service.common.ErrorCode;
import com.auth.auth_service.common.ErrorResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;

import org.springframework.http.MediaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter{
    private final JwtService jwtService;
    private final CustomUserDetailsService customUserDetailsService;
    private final ObjectMapper objectMapper;
    private final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class.getName());

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        try {
            String authHeader = request.getHeader("Authorization");
            
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                boolean isValid = jwtService.isTokenValid(token);

                if (!isValid) {
                    filterChain.doFilter(request, response);
                    return;
                }

                String userId = jwtService.extractUserId(token);

                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    try {
                        AuthUserDetails userDetails = (AuthUserDetails) customUserDetailsService.loadUserByUsername(userId);
                        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    } catch (UsernameNotFoundException e) {
                        logger.debug("User not found: {}", userId);
                    }
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            logger.error("Unexpected error in JwtAuthFilter", e);
            SecurityContextHolder.clearContext();
            response.setStatus(500);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            objectMapper.writeValue(
                    response.getWriter(),
                    ErrorResponse.of(ErrorCode.INTERNAL_SERVER_ERROR,
                        "Unexpected server error", request.getRequestURI()));
            return;
        }
    }
}
