package com.bitbox.gateway.filter;

import com.bitbox.gateway.util.JwtUtil;
import io.github.bitbox.bitbox.enums.AuthorityType;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class AdminAuthorizationFilter extends AbstractGatewayFilterFactory<AdminAuthorizationFilter.Config> {
    private final JwtUtil jwtUtil;

    public static class Config {

    }

    public AdminAuthorizationFilter(JwtUtil jwtUtil) {
        super(AdminAuthorizationFilter.Config.class);
        this.jwtUtil = jwtUtil;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if(!isAuthorized(getHeaderMemberAuthority(request))) {
                return onError(response, HttpStatus.FORBIDDEN);
            }

            return chain.filter(exchange);
        });
    }

    private String getHeaderMemberAuthority(ServerHttpRequest request) {
        return request.getHeaders().get("memberAuthority").get(0);
    }

    private boolean isAuthorized(String header) {
        return header.equals(AuthorityType.ADMIN.name()) ||
                header.equals(AuthorityType.MANAGER.name()) ||
                header.equals(AuthorityType.TEACHER.name());
    }

    private Mono<Void> onError(ServerHttpResponse response, HttpStatus status) {
        response.setStatusCode(status);
        return response.setComplete();
    }
}
