package com.codingshuttle.ecommerce.api_gateway.services;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Service

public class JwtService {

    @Value("${jwt.secretKey}") // link of the secret key from application.properties
    private String jwtKey;

    private SecretKey getSecretKey() { // method to get the secret key by a method so this method can be use directly
        // in signWith()
        return Keys.hmacShaKeyFor(jwtKey.getBytes(StandardCharsets.UTF_8));

    }



    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return Long.valueOf(claims.getSubject());
    }
    public List<String> getUserRolesFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.get("roles", List.class);
    }

}
