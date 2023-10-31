package com.bitbox.gateway.filter;

import com.bitbox.gateway.util.JwtUtil;
import io.jsonwebtoken.Claims;
import org.apache.http.HttpHeaders;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

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

            // 로그인 시에만 토큰 Parse
            if(containsAuthorization(request) && !getJwt(request).isBlank()) {
                Claims claims = jwtUtil.parse(getJwt(request));
                if(isExpired(claims)) {
                    return onError(response, HttpStatus.UNAUTHORIZED);
                }

                jwtUtil.addJwtPayloadHeaders(request, claims);

                return chain.filter(exchange);
            }

            // 비로그인 시 그냥 통과.
            return chain.filter(exchange);
        });
    }

    private boolean containsAuthorization(ServerHttpRequest request) {
        return request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
    }

    private boolean isExpired(Claims claims) {
        return claims.getExpiration().getTime() < System.currentTimeMillis();
    }

    private String getJwt(ServerHttpRequest request) {
        return request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0).replace("Bearer", "");
    }

    private Mono<Void> onError(ServerHttpResponse response, HttpStatus status) {
        response.setStatusCode(status);
        return response.setComplete();
    }
}
