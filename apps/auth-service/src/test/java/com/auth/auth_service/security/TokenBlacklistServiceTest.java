package com.auth.auth_service.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Pure unit tests for TokenBlacklistService.
 * No real Redis — StringRedisTemplate is mocked, same pattern as
 * AuthServiceTest mocking UserRepository.
 */
@ExtendWith(MockitoExtension.class)
class TokenBlacklistServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private TokenBlacklistService tokenBlacklistService;

    // ── blacklist() ────────────────────────────────────────────────────────────

    @Test
    void blacklist_positiveTtl_writesKeyWithThatTtl() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        tokenBlacklistService.blacklist("jti-1", Duration.ofMinutes(5));

        verify(valueOperations).set(eq("blacklist:jti:jti-1"), anyString(), eq(Duration.ofMinutes(5)));
    }

    @Test
    void blacklist_zeroTtl_writesNothing() {
        // A token that expired the instant logout ran needs no blacklist entry —
        // isTokenValid() already rejects it on expiry alone.
        tokenBlacklistService.blacklist("jti-1", Duration.ZERO);

        verify(redisTemplate, never()).opsForValue();
    }

    @Test
    void blacklist_negativeTtl_writesNothing() {
        // Defensive: a clock skew or an already-expired token must not write
        // a negative-TTL key (Redis semantics for that are provider-specific).
        tokenBlacklistService.blacklist("jti-1", Duration.ofSeconds(-1));

        verify(redisTemplate, never()).opsForValue();
    }

    // ── isBlacklisted() ────────────────────────────────────────────────────────

    @Test
    void isBlacklisted_keyPresent_returnsTrue() {
        when(redisTemplate.hasKey("blacklist:jti:jti-1")).thenReturn(true);

        assertThat(tokenBlacklistService.isBlacklisted("jti-1")).isTrue();
    }

    @Test
    void isBlacklisted_keyAbsent_returnsFalse() {
        when(redisTemplate.hasKey("blacklist:jti:jti-1")).thenReturn(false);

        assertThat(tokenBlacklistService.isBlacklisted("jti-1")).isFalse();
    }

    @Test
    void isBlacklisted_hasKeyReturnsNull_returnsFalse() {
        // StringRedisTemplate#hasKey is a Boolean, not boolean — a null (e.g.
        // a transient connection hiccup) must fail closed to "not blacklisted",
        // not throw a NullPointerException while unboxing.
        when(redisTemplate.hasKey(anyString())).thenReturn(null);

        assertThat(tokenBlacklistService.isBlacklisted("jti-1")).isFalse();
    }

    @Test
    void isBlacklisted_queriesTheSameKeyBlacklistWrote() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(redisTemplate.hasKey(anyString())).thenReturn(false);

        tokenBlacklistService.blacklist("shared-jti", Duration.ofMinutes(1));
        tokenBlacklistService.isBlacklisted("shared-jti");

        verify(redisTemplate).hasKey("blacklist:jti:shared-jti");
    }
}
