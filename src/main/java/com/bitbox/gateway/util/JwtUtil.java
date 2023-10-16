package com.bitbox.gateway.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.core.env.Environment;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.Key;

@Component
public class JwtUtil {

    private final Key key;

    private final JwtParser jwtParser;

    public JwtUtil(Environment env) {
        this.key = new SecretKeySpec(
                DatatypeConverter.parseBase64Binary(env.getProperty("jwt.secret")),
                SignatureAlgorithm.HS256.getJcaName());
        this.jwtParser = Jwts.parser();
    }

    public Claims parse(String jwt) {
        return jwtParser.setSigningKey(key).parseClaimsJws(jwt).getBody();
    }

    private String getMemberId(Claims claims) {
        return claims.get("member_id", String.class);
    }

    private String getMemberNickname(Claims claims) {
        return URLEncoder.encode(claims.get("member_nickname", String.class), StandardCharsets.UTF_8);
    }

    private Long getClassId(Claims claims) {
        return claims.get("class_id", Long.class);
    }

    private String getMemberAuthority(Claims claims) {
        return claims.get("member_authority", String.class);
    }

    public void addJwtPayloadHeaders(ServerHttpRequest request, Claims claims) {
        request.mutate()
                .header("Content-Type", "application/json;charset=UTF-8")
                .header("member_id", getMemberId(claims))
                .header("member_authority", getMemberAuthority(claims))
                .header("class_id", String.valueOf(getClassId(claims))) // header에 long이 안되네? null이면 "null"로 들어가긴 함 (NPE X)
                .header("member_nickname", getMemberNickname(claims))
                .build();
    }
}
