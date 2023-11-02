package com.bitbox.gateway.filter;

import com.bitbox.gateway.util.FilterUtil;
import com.bitbox.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

@Component
public class TokenParseFilter extends AbstractGatewayFilterFactory<TokenParseFilter.Config> {
    private final JwtUtil jwtUtil;

    public static class Config {

    }

    public TokenParseFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            // 로그인 시에만 토큰 Parse -> Authorization: Bearer null
            if(FilterUtil.containsAuthorizationHeader(request) && !FilterUtil.getJwt(request).isEmpty())  {
                Claims claims;
                try {
                    claims = jwtUtil.parse(FilterUtil.getJwt(request));
                } catch(ExpiredJwtException e) {
                    return FilterUtil.onError(response, HttpStatus.UNAUTHORIZED);
                }

                jwtUtil.addJwtPayloadHeaders(request, claims);

                return chain.filter(exchange);
            }

            // 비로그인 시 그냥 통과.
            return chain.filter(exchange);
        });
    }
}
