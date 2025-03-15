package org.example.oauth2example.auth.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private Long expirationTime;

    public String generateToken(@NonNull String username) { // todo: Map<String, Object> extraClaims
        return Jwts.builder()
                //.setClaims(extraClaims)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setIssuer("http://localhost:8080/uz.pro.usm")
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(signKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key signKey() {
        byte[] bytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(bytes);
    }

    public boolean isValid(@NonNull String token) {
        try {
            Claims claims = getClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            log.warn("Token muddati tugagan: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            log.error("Token validatsiyasi xatosi: {}", e.getMessage());
            return false;
        }
    }

    public String getUsername(@NonNull String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    private Claims getClaims(String token) {
        try {
            return Jwts.parser()
                    .setSigningKey(signKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (Exception e) {
            throw new RuntimeException("Tokenni o'qishda xato: " + e.getMessage());
        }
    }
}

