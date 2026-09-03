package com.auth.auth_service.admin;

import com.auth.auth_service.admin.dto.UpdateUserStatusRequest;
import com.auth.auth_service.common.GlobalExceptionHandler;
import com.auth.auth_service.security.AuthEntryPoint;
import com.auth.auth_service.security.AuthUserDetails;
import com.auth.auth_service.security.CustomUserDetailsService;
import com.auth.auth_service.security.JwtService;
import com.auth.auth_service.security.SecurityConfig;
import com.auth.auth_service.security.TokenBlacklistService;
import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRepository;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * MockMvc slice tests for AdminController's @PreAuthorize("hasRole('ADMIN')")
 * gate — exercises the real JwtAuthFilter + SecurityConfig (including
 * @EnableMethodSecurity), same shape as AuthControllerTest's /me tests. The
 * whole point of these tests is confirming a non-admin gets 403 (via the new
 * AccessDeniedException handler on GlobalExceptionHandler), not the 500 that
 * would happen without it — and that @EnableMethodSecurity is actually wired,
 * since @PreAuthorize is a silent no-op without it.
 */
@WebMvcTest(AdminController.class)
@Import({GlobalExceptionHandler.class, AuthEntryPoint.class, SecurityConfig.class})
class AdminControllerTest {

    private static final String VALID_TOKEN = "valid.jwt.token";
    private static final UUID USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    @Autowired
    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @MockitoBean
    private UserRepository userRepository;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private TokenBlacklistService tokenBlacklistService;

    private User userWithRole(UserRole role) {
        User user = new User("user@example.com", "hashed", "testuser", role, UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user, "id", USER_ID);
        return user;
    }

    private void stubAuthenticatedRequest(User user) {
        when(jwtService.isTokenValid(VALID_TOKEN)).thenReturn(true);
        when(jwtService.extractJti(VALID_TOKEN)).thenReturn("jti-1");
        when(tokenBlacklistService.isBlacklisted("jti-1")).thenReturn(false);
        when(jwtService.extractUserId(VALID_TOKEN)).thenReturn(user.getId().toString());
        when(customUserDetailsService.loadUserByUsername(user.getId().toString()))
                .thenReturn(new AuthUserDetails(user));
    }

    @Test
    void listUsers_noAuthorizationHeader_returns401() throws Exception {
        mockMvc.perform(get("/api/v1/admin/users"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void listUsers_regularUser_returns403NotInternalServerError() throws Exception {
        stubAuthenticatedRequest(userWithRole(UserRole.USER));

        mockMvc.perform(get("/api/v1/admin/users").header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void listUsers_adminUser_returns200() throws Exception {
        stubAuthenticatedRequest(userWithRole(UserRole.ADMIN));
        when(userRepository.findAll()).thenReturn(List.of(userWithRole(UserRole.USER)));

        mockMvc.perform(get("/api/v1/admin/users").header("Authorization", "Bearer " + VALID_TOKEN))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].email").value("user@example.com"));
    }

    @Test
    void updateStatus_regularUser_returns403() throws Exception {
        stubAuthenticatedRequest(userWithRole(UserRole.USER));

        mockMvc.perform(patch("/api/v1/admin/users/{id}/status", USER_ID)
                        .header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateUserStatusRequest(UserStatus.DISABLED))))
                .andExpect(status().isForbidden());
    }

    @Test
    void updateStatus_adminUser_returns200() throws Exception {
        stubAuthenticatedRequest(userWithRole(UserRole.ADMIN));
        User target = userWithRole(UserRole.USER);
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(target));
        when(userRepository.save(any())).thenReturn(target);

        mockMvc.perform(patch("/api/v1/admin/users/{id}/status", USER_ID)
                        .header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateUserStatusRequest(UserStatus.DISABLED))))
                .andExpect(status().isOk());
    }

    @Test
    void updateStatus_adminUser_userNotFound_returns404() throws Exception {
        stubAuthenticatedRequest(userWithRole(UserRole.ADMIN));
        when(userRepository.findById(USER_ID)).thenReturn(Optional.empty());

        mockMvc.perform(patch("/api/v1/admin/users/{id}/status", USER_ID)
                        .header("Authorization", "Bearer " + VALID_TOKEN)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(new UpdateUserStatusRequest(UserStatus.DISABLED))))
                .andExpect(status().isNotFound());
    }
}
