package com.bitbox.gateway.util;

import org.apache.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import reactor.core.publisher.Mono;

public class FilterUtil {

    public static Mono<Void> onError(ServerHttpResponse response, HttpStatus status) {
        response.setStatusCode(status);
        return response.setComplete();
    }

    public static boolean containsAuthorizationHeader(ServerHttpRequest request) {
        return request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
    }

    public static String getHeaderMemberAuthority(ServerHttpRequest request) {
        return request.getHeaders().get("memberAuthority").get(0);
    }

    public static String getJwt(ServerHttpRequest request) {
        return request.getHeaders().get(HttpHeaders.AUTHORIZATION).get(0).replace("Bearer", "");
    }
}
