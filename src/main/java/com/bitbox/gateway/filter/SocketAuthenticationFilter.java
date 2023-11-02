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
public class SocketAuthenticationFilter extends AbstractGatewayFilterFactory<SocketAuthenticationFilter.Config> {

    private final JwtUtil jwtUtil;

    public static class Config {

    }

    public SocketAuthenticationFilter(JwtUtil jwtUtil) {
        super(Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if (!containsAuthorization(request)) {
                return FilterUtil.onError(response, HttpStatus.UNAUTHORIZED);
            }

            Claims claims;
            try {
                claims = jwtUtil.parse(FilterUtil.getJwt(request));
            } catch(MalformedJwtException | ExpiredJwtException e) {
                return FilterUtil.onError(response, HttpStatus.UNAUTHORIZED);
            }

            jwtUtil.addJwtPayloadHeaders(request, claims);

            return chain.filter(exchange);
        });
    }

    private boolean containsAuthorization(ServerHttpRequest request) {
        return request.getQueryParams().getFirst("sessionToken") != null;
    }

    private String getJwt(ServerHttpRequest request) {
        return request.getQueryParams().getFirst("sessionToken").replace("Bearer", "");
    }
}