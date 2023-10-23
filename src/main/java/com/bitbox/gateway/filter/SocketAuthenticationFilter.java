package com.bitbox.gateway.filter;

import com.bitbox.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

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

            if(!containsAuthorization(request)) {
                return onError(response, HttpStatus.UNAUTHORIZED);
            }

            Claims claims = jwtUtil.parse(getJwt(request));
            if(isExpired(claims)) {
                return onError(response, HttpStatus.UNAUTHORIZED);
            }

            jwtUtil.addJwtPayloadHeaders(request, claims);

            return chain.filter(exchange);
        });
    }

    private boolean containsAuthorization(ServerHttpRequest request) {
        return request.getQueryParams().getFirst("sessionToken") != null;
    }

    private boolean isExpired(Claims claims) {
        return claims.getExpiration().getTime() < System.currentTimeMillis();
    }

    private String getJwt(ServerHttpRequest request) {
        return request.getQueryParams().getFirst("sessionToken").replace("Bearer", "");
    }

    private Mono<Void> onError(ServerHttpResponse response, HttpStatus status) {
        response.setStatusCode(status);
        return response.setComplete();
    }
}