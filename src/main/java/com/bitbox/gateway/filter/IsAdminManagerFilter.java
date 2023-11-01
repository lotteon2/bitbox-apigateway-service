package com.bitbox.gateway.filter;

import com.bitbox.gateway.util.FilterUtil;
import io.github.bitbox.bitbox.enums.AuthorityType;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;

@Component
public class IsAdminManagerFilter extends AbstractGatewayFilterFactory<IsAdminManagerFilter.Config> {

    public static class Config {

    }

    public IsAdminManagerFilter() {
        super(IsAdminManagerFilter.Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            if(!isAuthorized(FilterUtil.getHeaderMemberAuthority(request))) {
                return FilterUtil.onError(response, HttpStatus.FORBIDDEN);
            }

            return chain.filter(exchange);
        });
    }

    private boolean isAuthorized(String header) {
        return header.equals(AuthorityType.ADMIN.name()) ||
                header.equals(AuthorityType.MANAGER.name());
    }
}
