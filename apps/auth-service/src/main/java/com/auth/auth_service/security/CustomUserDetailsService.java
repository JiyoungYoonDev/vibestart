package com.auth.auth_service.security;

import java.util.UUID;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.auth.auth_service.user.UserRepository;
import com.auth.auth_service.user.User;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public AuthUserDetails loadUserByUsername(String userId) {
        UUID userUUID = UUID.fromString(userId);
        
        User user = userRepository.findById(userUUID)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + userId));

        return new AuthUserDetails(user);

    }
    
}
