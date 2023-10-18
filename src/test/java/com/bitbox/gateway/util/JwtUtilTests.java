package com.bitbox.gateway.util;

import io.github.bitbox.bitbox.enums.AuthorityType;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.logging.Logger;

@SpringBootTest
@ActiveProfiles("dev")
public class JwtUtilTests {
    Logger logger = Logger.getLogger("JwtUtilTest");

    @Autowired
    JwtUtil jwtUtil;
    String testJwt = "eyJ0eXAiOiJBQ0NFU1MiLCJhbGciOiJIUzI1NiJ9.eyJtZW1iZXJfaWQiOiJVVUlEIiwibWVtYmVyX25pY2tuYW1lIjoibWFuYWdlciIsImNsYXNzX2lkIjpudWxsLCJtZW1iZXJfYXV0aG9yaXR5IjoiTUFOQUdFUiIsImV4cCI6MTY5NzM4NDk3N30.kLSTdWe_UnqeD6XP7v3gL_I3CZ88lOM1i-kNjkAEw3M";

    @Test
    @DisplayName("추출 테스트")
    void parseJwtTest() {
        Claims claims = jwtUtil.parse(testJwt);

        assert claims.get("memberId", String.class).equals("UUID");
        assert claims.get("memberNickname", String.class).equals("manager");
        assert claims.get("classId", Long.class) == null;
        assert claims.getExpiration().getTime() > System.currentTimeMillis();
        assert claims.get("memberAuthority", String.class).equals(AuthorityType.MANAGER.name());
    }
}
