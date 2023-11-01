package com.bitbox.gateway.filter;

import com.bitbox.gateway.util.FilterUtil;
import com.bitbox.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final JwtUtil jwtUtil;

    public static class Config {

    }

    public AuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if(!FilterUtil.containsAuthorizationHeader(request) || FilterUtil.getJwt(request).isBlank()) {
                return FilterUtil.onError(response, HttpStatus.UNAUTHORIZED);
            }

            Claims claims = jwtUtil.parse(FilterUtil.getJwt(request));
            if(jwtUtil.isExpired(claims)) {
                return FilterUtil.onError(response, HttpStatus.UNAUTHORIZED);
            }

            jwtUtil.addJwtPayloadHeaders(request, claims);

            return chain.filter(exchange);
        });
    }
}
