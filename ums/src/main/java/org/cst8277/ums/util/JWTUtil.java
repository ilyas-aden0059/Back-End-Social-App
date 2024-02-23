package org.cst8277.ums.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JWTUtil {
    private static final String SECRET_KEY = "eqdvNxW4PQd3RdHq1AK4V1Ozy9RWcTN4rcBczbI+viufos0vLM7DOO1YPuqLRwvX\n";

    public static String generateToken(String username, String id)
    {
        Key signingKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
        long nowMillis = System.currentTimeMillis();
        Date issuedAt = new Date(nowMillis);

        long expirationMillis = nowMillis + 3600000;
        Date expiration = new Date(expirationMillis);

        return Jwts.builder()
                .setSubject(username)
                .claim("login", id)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }


    public static String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public static String extractId(String token) {
        return extractClaim(token, claims -> claims.get("login", String.class));
    }

    private static <T> T extractClaim(String token, ClaimsResolver<T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private static Claims extractAllClaims(String token) {
        Key signingKey = Keys.hmacShaKeyFor(SECRET_KEY.getBytes());
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    @FunctionalInterface
    public interface ClaimsResolver<T> {
        T apply(Claims claims);
    }
}
