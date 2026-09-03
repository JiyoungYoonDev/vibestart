package com.auth.auth_service.security;

import java.time.Duration;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

/**
 * JWTs are stateless — logging out can't delete a token, only mark its jti
 * revoked here until the token's own expiry would have retired it anyway.
 * Keyed by jti (not the full token) so a revoked entry never outlives the
 * key it protects: the Redis TTL is set to exactly the token's own
 * remaining lifetime, so this collection self-cleans instead of growing
 * forever.
 */
@Service
@RequiredArgsConstructor
public class TokenBlacklistService {
    private static final String KEY_PREFIX = "blacklist:jti:";

    private final StringRedisTemplate redisTemplate;

    public void blacklist(String jti, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero()) {
            return;
        }
        redisTemplate.opsForValue().set(KEY_PREFIX + jti, "1", ttl);
    }

    public boolean isBlacklisted(String jti) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + jti));
    }
}
