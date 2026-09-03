package com.auth.auth_service.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import lombok.RequiredArgsConstructor;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;

// @EnableMethodSecurity is required for @PreAuthorize to do anything at
// all — without it the annotation is silently a no-op (no compile error,
// the check just never fires). Needed for AdminController's
// hasRole('ADMIN') checks.
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtAuthFilter jwtAuthFilter;
    private final AuthEntryPoint authEntryPoint;

    // Spring Boot auto-registers every Filter @Component as its own standalone
    // servlet filter — running before Spring Security's whole filter chain,
    // completely separate from the addFilterBefore(jwtAuthFilter, ...) wiring
    // below. Left alone, JwtAuthFilter ran TWICE per request: once out here
    // (setting SecurityContextHolder before Spring Security's own
    // SecurityContextHolderFilter resets it for the real chain) and once
    // properly-positioned inside the chain — the outer pass's work was thrown
    // away every time, and a valid token still failed .anyRequest().authenticated()
    // as if unauthenticated. Disabling the auto-registration leaves exactly
    // one execution, at the position addFilterBefore actually puts it.
    @Bean
    public FilterRegistrationBean<JwtAuthFilter> jwtAuthFilterRegistration(JwtAuthFilter filter) {
        FilterRegistrationBean<JwtAuthFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .exceptionHandling(ex -> ex.authenticationEntryPoint(authEntryPoint))
            .authorizeHttpRequests(auth ->
                // Was a blanket "/api/v1/auth/**" permitAll, which covered
                // /me and /logout too — those need @AuthenticationPrincipal
                // to actually be populated, so an unauthenticated request
                // was reaching the controller with a null principal and
                // dying with a 500 (NPE) instead of the intended 401. Only
                // signup/login are genuinely public; /me and /logout now
                // fall through to .anyRequest().authenticated() below.
                //
                // Path-only (no HttpMethod restriction): a GET on these
                // POST-only endpoints still needs to reach Spring MVC's own
                // dispatcher to get the correct 405, not get turned away
                // with a 401 by the security layer before MVC ever sees it.
                // Confirmed live: a browser's CORS preflight (OPTIONS) never
                // carries the Authorization header, so without this,
                // .anyRequest().authenticated() below 401'd the preflight
                // itself for every protected endpoint (/me, /logout) — the
                // browser then blocks the real GET/POST before it's even
                // sent, since a failed preflight has no Access-Control-*
                // headers to approve it. Signup/login never showed this
                // (already permitAll), which is why it stayed hidden until
                // an actually-protected endpoint was exercised from a browser.
                auth.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/api/v1/auth/signup", "/api/v1/auth/login", "/api/v1/auth/google").permitAll()
                // Was "/actuator/health" — HealthController actually serves
                // "/api/v1/health" (+ /readiness, /liveness), never
                // "/actuator/health" (no actuator dependency is even on this
                // project's classpath) — the real health check was 401'ing,
                // which breaks any docker/k8s healthcheck pointed at it.
                .requestMatchers("/api/v1/health/**").permitAll()
                    .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
