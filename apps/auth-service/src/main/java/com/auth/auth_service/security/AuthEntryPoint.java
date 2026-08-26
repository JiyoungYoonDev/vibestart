package com.auth.auth_service.security;

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.auth.auth_service.common.ErrorCode;
import com.auth.auth_service.common.ErrorResponse;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.AuthenticationException;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import tools.jackson.databind.ObjectMapper;                                     

@Component
@RequiredArgsConstructor
public class AuthEntryPoint implements AuthenticationEntryPoint{
    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        ErrorResponse<Void> errorResponse = ErrorResponse.of(ErrorCode.UNAUTHORIZED, "Authentication required", request.getRequestURI());
        response.setStatus(401);
        response.setContentType("application/json");
        objectMapper.writeValue(response.getWriter(), errorResponse);
    }

}
