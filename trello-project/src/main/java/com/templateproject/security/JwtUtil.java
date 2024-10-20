package com.templateproject.security;

import com.templateproject.common.enums.TokenType;
import com.templateproject.common.enums.UserRole;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;

@Slf4j(topic = "JWT Util")
@Component
public class JwtUtil {

    // Header KEY 값
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String REFRESH_TOKEN_HEADER = "Refresh-Token";
    public static final String REDIS_REFRESH_TOKEN_PREFIX = "Refresh_";

    // Token 식별자
    public static final String BEARER_PREFIX = "Bearer ";

    @Value("${JWT_SECRET_TOKEN}")
    private String secretKey;

    private SecretKey key;

    @PostConstruct
    private void init() {
        // 키 설정
        key = getSecretKeyFromBase64(secretKey);
    }

    public String substringToken(String token) {
        if (StringUtils.hasText(token) && token.startsWith(BEARER_PREFIX)) {
            return token.substring(BEARER_PREFIX.length());
        }

        log.error("Not Found Token");
        throw new NullPointerException("Not Found Token");
    }

    public String getUserId(String token) {
        return getJwtParser().parseSignedClaims(token)
            .getPayload().getSubject();
    }

    public boolean isExpired(String token) {
        return getJwtParser().parseSignedClaims(token)
            .getPayload()
            .getExpiration()
            .before(new Date());
    }

    public String getTokenCategory(String token) {
        return getJwtParser().parseSignedClaims(token)
            .getPayload()
            .get("category", String.class);
    }

    public String createAccessToken(Long userId, String email, UserRole role) {
        Date now = new Date();
        return BEARER_PREFIX + Jwts.builder()
            .claim("category", TokenType.ACCESS.name())
            .expiration(new Date(now.getTime() + TokenType.ACCESS.getLifeTime()))
            .subject(String.valueOf(userId))
            .claim("email", email)
            .claim("userRole", role.getUserRole())
            .issuedAt(now)
            .signWith(key)
            .compact();
    }

    public String createRefreshToken(Long userId, String email,  UserRole role) {
        Date now = new Date();
        return BEARER_PREFIX + Jwts.builder()
            .claim("category", TokenType.REFRESH.name())
            .expiration(new Date(now.getTime() + TokenType.REFRESH.getLifeTime()))
            .subject(String.valueOf(userId))
            .claim("email", email)
            .claim("userRole", role.getUserRole())
            .issuedAt(now)
            .signWith(key)
            .compact();
    }

    public Claims extractClaims(String token) {
        return getJwtParser().parseSignedClaims(token).getPayload();
    }

    private JwtParser getJwtParser() {
        return Jwts.parser()
            .verifyWith(key)
            .build();
    }

    private SecretKey getSecretKeyFromBase64(String base64) {
        return Keys.hmacShaKeyFor(Base64Coder.decode(base64));
    }
}