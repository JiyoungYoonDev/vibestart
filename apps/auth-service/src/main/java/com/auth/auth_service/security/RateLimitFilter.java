package com.auth.auth_service.security;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.Refill;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * First-pass, per-IP rate limiting on the account-security-sensitive
 * endpoints: login/signup/Google sign-in (credential stuffing, mass account
 * creation) and change-password. /me and /logout are left unmatched —
 * they're read-mostly and already require a valid token.
 *
 * In-memory only, even though this service also has Redis wired up (for
 * TokenBlacklistService) — it runs as a single Railway instance today, so
 * a shared store buys nothing yet. If this service is ever scaled to
 * multiple instances, swap the Caffeine-backed bucket store for a
 * bucket4j-redis proxy manager so all instances share one budget.
 *
 * Plain @Component filters auto-register standalone, ahead of the whole
 * Spring Security chain (see the comment on this same trick in
 * SecurityConfig's jwtAuthFilterRegistration bean) — exactly what's wanted
 * here: reject before JWT parsing or a DB lookup ever run.
 *
 * Gated off by default in tests (rate-limit.enabled=false in
 * src/test/resources/application.yml, loaded for every test in this
 * module regardless of active profile): @WebMvcTest slices auto-detect any
 * Filter @Component in the app's base package — same as JwtAuthFilter,
 * see AuthControllerTest's own comment on that — so without this, a test
 * class that legitimately calls e.g. /signup more than 5 times (this
 * filter's hourly budget) starts failing on unrelated assertions once the
 * shared bucket for that class's cached ApplicationContext runs dry.
 */
@Component
@ConditionalOnProperty(name = "rate-limit.enabled", havingValue = "true", matchIfMissing = true)
public class RateLimitFilter extends OncePerRequestFilter {
    private record Rule(HttpMethod method, String pathPattern, int capacity, Duration window) {
        String id() {
            return (method == null ? "*" : method.name()) + " " + pathPattern;
        }
    }

    private static final List<Rule> RULES = List.of(
        new Rule(HttpMethod.POST, "/api/v1/auth/login", 10, Duration.ofMinutes(1)),
        new Rule(HttpMethod.POST, "/api/v1/auth/google", 10, Duration.ofMinutes(1)),
        new Rule(HttpMethod.POST, "/api/v1/auth/signup", 5, Duration.ofHours(1)),
        new Rule(HttpMethod.POST, "/api/v1/auth/change-password", 5, Duration.ofHours(1)),
        new Rule(null, "/api/v1/admin/**", 60, Duration.ofMinutes(1))
    );

    private static final AntPathMatcher PATH_MATCHER = new AntPathMatcher();

    // expireAfterAccess must outlast the longest rule window (1 hour) — see
    // the identical note on woojoo-shop backend's RateLimitFilter for why.
    private final Cache<String, Bucket> buckets = Caffeine.newBuilder()
        .expireAfterAccess(Duration.ofHours(2))
        .maximumSize(100_000)
        .build();

    private static Rule matchRule(String method, String path) {
        for (Rule rule : RULES) {
            if (rule.method() != null && !rule.method().name().equals(method)) continue;
            if (PATH_MATCHER.match(rule.pathPattern(), path)) return rule;
        }
        return null;
    }

    private static Bucket newBucket(Rule rule) {
        Bandwidth limit = Bandwidth.classic(rule.capacity(), Refill.greedy(rule.capacity(), rule.window()));
        return Bucket.builder().addLimit(limit).build();
    }

    // Railway's edge proxy appends the real client IP as the last hop of
    // X-Forwarded-For — reading the last entry (rather than the first,
    // which a client can freely spoof in their own request) is the safer
    // default for a single-trusted-proxy deployment like this one.
    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            String[] hops = forwarded.split(",");
            return hops[hops.length - 1].trim();
        }
        return request.getRemoteAddr();
    }

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        Rule rule = matchRule(request.getMethod(), request.getRequestURI());
        if (rule == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String key = clientIp(request) + "|" + rule.id();
        Bucket bucket = buckets.get(key, k -> newBucket(rule));
        ConsumptionProbe probe = bucket.tryConsumeAndReturnRemaining(1);

        if (probe.isConsumed()) {
            response.setHeader("X-RateLimit-Remaining", String.valueOf(probe.getRemainingTokens()));
            filterChain.doFilter(request, response);
            return;
        }

        long retryAfterSeconds = Math.max(1, probe.getNanosToWaitForRefill() / 1_000_000_000);
        response.setStatus(429);
        response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        response.setContentType("application/json");
        response.getWriter().write(
            "{\"error\":\"Too many requests. Try again in " + retryAfterSeconds + " seconds.\"}"
        );
    }
}
