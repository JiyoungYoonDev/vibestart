package com.auth.auth_service.security;

import com.auth.auth_service.user.User;
import com.auth.auth_service.user.UserRole;
import com.auth.auth_service.user.UserStatus;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.test.util.ReflectionTestUtils;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Pure unit tests for JwtService.
 * No Spring context — JwtProperties is constructed directly.
 * Real jjwt library is used to sign and parse tokens,
 * so the cryptographic behaviour is actually exercised.
 *
 * Test key: 256-bit HMAC-SHA key encoded as Base64 (test-only, never production).
 */
class JwtServiceTest {

    // 256-bit key (32 bytes) encoded in Base64 — satisfies HS256 minimum key length
    private static final String TEST_SECRET =
            "dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtbG9uZy1lbm91Z2gtZm9yLUhTMjU2";
    private static final long EXPIRATION_MS = 3_600_000L; // 1 hour

    private JwtService jwtService;
    private SecretKey verifyKey;

    @BeforeEach
    void setUp() {
        JwtProperties properties = new JwtProperties(TEST_SECRET, EXPIRATION_MS);
        jwtService = new JwtService(properties);

        // Independent signing key for test-side verification
        byte[] keyBytes = Base64.getDecoder().decode(TEST_SECRET);
        verifyKey = Keys.hmacShaKeyFor(keyBytes);
    }

    // ── helper: parse a token with the same key used for signing ─────────────
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(verifyKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Injects a UUID into User.id via ReflectionTestUtils.
     * User.id is assigned by JPA (@GeneratedValue) and has no setter,
     * so ReflectionTestUtils is the idiomatic Spring way to set it in tests.
     */
    private User userWithRole(UserRole role) {
        User user = new User("test@example.com", "hashed", "testuser", role, UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user, "id", UUID.fromString("00000000-0000-0000-0000-000000000001"));
        return user;
    }

    // ── Token structure ───────────────────────────────────────────────────────

    @Test
    void generateToken_returnsNonNullToken() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(token).isNotNull().isNotBlank();
    }

    @Test
    void generateToken_tokenHasThreeJwtParts() {
        // A compact JWT has exactly 3 Base64url segments separated by '.'
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(token.split("\\.")).hasSize(3);
    }

    @Test
    void generateToken_tokenIsVerifiableWithSameKey() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        // Parsing throws if signature is invalid — no exception means success
        Claims claims = parseClaims(token);
        assertThat(claims).isNotNull();
    }

    // ── Claims: subject (user id) ─────────────────────────────────────────────

    @Test
    void generateToken_subjectIsUserId() {
        User user = userWithRole(UserRole.USER);
        String token = jwtService.generateToken(user);

        // Subject must be the user's UUID as a string
        assertThat(parseClaims(token).getSubject())
                .isEqualTo("00000000-0000-0000-0000-000000000001");
    }

    // ── Claims: email ─────────────────────────────────────────────────────────

    @Test
    void generateToken_emailClaimMatchesUserEmail() {
        User user = userWithRole(UserRole.USER);
        String token = jwtService.generateToken(user);

        assertThat(parseClaims(token).get("email", String.class))
                .isEqualTo("test@example.com");
    }

    private User userWithEmail(String email, UUID id) {
        User user = new User(email, "hashed", email.split("@")[0], UserRole.USER, UserStatus.ACTIVE);
        ReflectionTestUtils.setField(user, "id", id);
        return user;
    }

    @Test
    void generateToken_differentUsersProduceDifferentEmailClaims() {
        User user1 = userWithEmail("alice@example.com", UUID.fromString("00000000-0000-0000-0000-000000000001"));
        User user2 = userWithEmail("bob@example.com",   UUID.fromString("00000000-0000-0000-0000-000000000002"));

        String email1 = parseClaims(jwtService.generateToken(user1)).get("email", String.class);
        String email2 = parseClaims(jwtService.generateToken(user2)).get("email", String.class);

        assertThat(email1).isEqualTo("alice@example.com");
        assertThat(email2).isEqualTo("bob@example.com");
    }

    // ── Claims: role ──────────────────────────────────────────────────────────

    @Test
    void generateToken_roleClaimIsUserForUserRole() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(parseClaims(token).get("role", String.class)).isEqualTo("USER");
    }

    @Test
    void generateToken_roleClaimIsAdminForAdminRole() {
        String token = jwtService.generateToken(userWithRole(UserRole.ADMIN));

        assertThat(parseClaims(token).get("role", String.class)).isEqualTo("ADMIN");
    }

    // ── Claims: issuedAt / expiration ─────────────────────────────────────────

    @Test
    void generateToken_issuedAtIsBeforeOrEqualToNow() {
        // jjwt truncates issuedAt to second precision (epoch seconds).
        // We align the boundary to the same precision to avoid false negatives.
        long beforeSec = System.currentTimeMillis() / 1000;
        String token = jwtService.generateToken(userWithRole(UserRole.USER));
        long afterSec = System.currentTimeMillis() / 1000;

        long issuedAtSec = parseClaims(token).getIssuedAt().getTime() / 1000;
        assertThat(issuedAtSec)
                .isGreaterThanOrEqualTo(beforeSec)
                .isLessThanOrEqualTo(afterSec);
    }

    @Test
    void generateToken_expirationIsIssuedAtPlusExpirationMs() {
        long before = System.currentTimeMillis();
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        Claims claims = parseClaims(token);
        long issuedAt = claims.getIssuedAt().getTime();
        long expiration = claims.getExpiration().getTime();

        // Allow 100ms clock drift between issuedAt capture and assertion
        assertThat(expiration - issuedAt)
                .isGreaterThanOrEqualTo(EXPIRATION_MS - 100)
                .isLessThanOrEqualTo(EXPIRATION_MS + 100);
    }

    @Test
    void generateToken_expirationIsInTheFuture() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        Date expiration = parseClaims(token).getExpiration();
        assertThat(expiration).isAfter(new Date());
    }

    // ── Expiration boundary: short-lived token ────────────────────────────────

    @Test
    void generateToken_alreadyExpiredToken_isRejectedByParser() throws InterruptedException {
        // Create a JwtService with 1ms expiration so the token expires immediately
        JwtProperties shortLived = new JwtProperties(TEST_SECRET, 1L);
        JwtService shortJwtService = new JwtService(shortLived);

        String token = shortJwtService.generateToken(userWithRole(UserRole.USER));

        Thread.sleep(10); // ensure the token has expired

        assertThatThrownBy(() -> parseClaims(token))
                .isInstanceOf(io.jsonwebtoken.ExpiredJwtException.class);
    }

    // ── Signature tamper ──────────────────────────────────────────────────────

    @Test
    void generateToken_tamperedSignature_isRejectedByParser() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        // Corrupt a character in the middle of the signature segment — the
        // *last* base64url character only encodes a few bits of the final
        // byte, so replacing it can occasionally decode to the same byte
        // value by chance, leaving the signature bytes (and the test)
        // unchanged. A middle character always flips a real byte.
        int mid = token.length() / 2;
        char replacement = token.charAt(mid) == 'X' ? 'Y' : 'X';
        String tampered = token.substring(0, mid) + replacement + token.substring(mid + 1);

        assertThatThrownBy(() -> parseClaims(tampered))
                .isInstanceOf(io.jsonwebtoken.security.SecurityException.class);
    }

    // ── Two tokens for same user are not identical (different iat) ────────────

    @Test
    void generateToken_calledTwiceForSameUser_producesDifferentTokensOverTime()
            throws InterruptedException {
        User user = userWithRole(UserRole.USER);

        String token1 = jwtService.generateToken(user);
        // jjwt uses second precision for issuedAt — sleep > 1s to guarantee different timestamps
        Thread.sleep(1100);
        String token2 = jwtService.generateToken(user);

        assertThat(token1).isNotEqualTo(token2);
    }

    // =========================================================================
    // extractUserId()
    // =========================================================================

    @Test
    void extractUserId_returnsCorrectUserId() {
        User user = userWithRole(UserRole.USER);
        String token = jwtService.generateToken(user);

        String userId = jwtService.extractUserId(token);

        assertThat(userId).isEqualTo("00000000-0000-0000-0000-000000000001");
    }

    @Test
    void extractUserId_differentUsersProduceDifferentIds() {
        User user1 = userWithEmail("alice@example.com", UUID.fromString("00000000-0000-0000-0000-000000000001"));
        User user2 = userWithEmail("bob@example.com",   UUID.fromString("00000000-0000-0000-0000-000000000002"));

        String id1 = jwtService.extractUserId(jwtService.generateToken(user1));
        String id2 = jwtService.extractUserId(jwtService.generateToken(user2));

        assertThat(id1).isEqualTo("00000000-0000-0000-0000-000000000001");
        assertThat(id2).isEqualTo("00000000-0000-0000-0000-000000000002");
    }

    // =========================================================================
    // isTokenValid()
    // =========================================================================

    @Test
    void isTokenValid_validToken_returnsTrue() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(jwtService.isTokenValid(token)).isTrue();
    }

    @Test
    void isTokenValid_expiredToken_returnsFalse() throws InterruptedException {
        // 1ms expiration — the token is expired by the time isTokenValid() runs
        JwtProperties shortLived = new JwtProperties(TEST_SECRET, 1L);
        JwtService shortJwtService = new JwtService(shortLived);

        String token = shortJwtService.generateToken(userWithRole(UserRole.USER));
        Thread.sleep(10);

        assertThat(shortJwtService.isTokenValid(token)).isFalse();
    }

    @Test
    void isTokenValid_tamperedToken_returnsFalse() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        // Corrupt a character in the middle of the signature segment — the
        // *last* base64url character only encodes a few bits of the final
        // byte, so replacing it can occasionally decode to the same byte
        // value by chance, leaving the signature bytes (and the test)
        // unchanged. A middle character always flips a real byte.
        int mid = token.length() / 2;
        char replacement = token.charAt(mid) == 'X' ? 'Y' : 'X';
        String tampered = token.substring(0, mid) + replacement + token.substring(mid + 1);

        assertThat(jwtService.isTokenValid(tampered)).isFalse();
    }

    @Test
    void isTokenValid_malformedToken_returnsFalse() {
        assertThat(jwtService.isTokenValid("not.a.jwt")).isFalse();
    }

    @Test
    void isTokenValid_emptyToken_returnsFalse() {
        assertThat(jwtService.isTokenValid("")).isFalse();
    }

    @Test
    void isTokenValid_tokenSignedWithDifferentKey_returnsFalse() {
        // Sign a structurally valid token with a completely different secret
        String otherSecret = Base64.getEncoder().encodeToString(
                "a-completely-different-256-bit-secret-key!!".getBytes());
        JwtService otherJwtService = new JwtService(new JwtProperties(otherSecret, EXPIRATION_MS));

        String token = otherJwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(jwtService.isTokenValid(token)).isFalse();
    }

    // =========================================================================
    // extractJti() — used by TokenBlacklistService to key a logout revocation
    // =========================================================================

    @Test
    void extractJti_returnsAParsableUuid() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        // Must not throw — jti is a UUID string
        assertThat(UUID.fromString(jwtService.extractJti(token))).isNotNull();
    }

    @Test
    void extractJti_matchesTheJtiClaimInTheToken() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(jwtService.extractJti(token)).isEqualTo(parseClaims(token).getId());
    }

    @Test
    void extractJti_calledTwiceForSameUser_producesDifferentJtis() {
        User user = userWithRole(UserRole.USER);

        String jti1 = jwtService.extractJti(jwtService.generateToken(user));
        String jti2 = jwtService.extractJti(jwtService.generateToken(user));

        // Two logins for the same user must be independently revocable
        assertThat(jti1).isNotEqualTo(jti2);
    }

    // =========================================================================
    // extractExpiration()
    // =========================================================================

    @Test
    void extractExpiration_matchesTheExpirationClaimInTheToken() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(jwtService.extractExpiration(token)).isEqualTo(parseClaims(token).getExpiration());
    }

    @Test
    void extractExpiration_isInTheFuture() {
        String token = jwtService.generateToken(userWithRole(UserRole.USER));

        assertThat(jwtService.extractExpiration(token)).isAfter(new Date());
    }
}
