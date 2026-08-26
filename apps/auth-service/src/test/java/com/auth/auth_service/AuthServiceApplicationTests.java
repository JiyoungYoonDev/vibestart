package com.auth.auth_service;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test: verifies the full Spring application context loads successfully.
 *
 * jwt.secret is overridden inline here (priority 12) to beat OS environment
 * variables (priority 5) that may contain a non-Base64 placeholder value.
 * The value is a test-only 256-bit Base64 key — never use in production.
 */
@SpringBootTest(properties = {
        "jwt.secret=dGVzdC1zZWNyZXQta2V5LXRoYXQtaXMtbG9uZy1lbm91Z2gtZm9yLUhTMjU2",
        "jwt.expiration-ms=3600000"
})
@ActiveProfiles("test")
class AuthServiceApplicationTests {

    @Test
    void contextLoads() {
    }

}
