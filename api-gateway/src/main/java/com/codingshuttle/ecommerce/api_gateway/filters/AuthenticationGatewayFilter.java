package com.codingshuttle.ecommerce.api_gateway.filters;

import com.codingshuttle.ecommerce.api_gateway.services.JwtService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;

@Component
@Slf4j

public class AuthenticationGatewayFilter extends AbstractGatewayFilterFactory<AuthenticationGatewayFilter.Config> {

    private final JwtService jwtService;

    public AuthenticationGatewayFilter(JwtService jwtService){
        super(Config.class);
        this.jwtService=jwtService;
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange,chain)->{

            if(!config.isEnabled){
                return chain.filter(exchange);
            }

            log.info("auth logging from:{}",exchange.getRequest().getURI());
            String authenticationHeader=exchange.getRequest().getHeaders().getFirst("Authentication");

            if(authenticationHeader==null){
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String token=authenticationHeader.split("Bearer ")[1];

            Long userId=jwtService.getUserIdFromToken(token);

            exchange.getRequest().mutate().header("X-User-Id",userId.toString());


            return chain.filter(exchange);
        };
    }

    @Data
    public static class Config{
      private boolean isEnabled;
    }

}
