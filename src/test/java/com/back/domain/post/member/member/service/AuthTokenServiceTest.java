package com.back.domain.post.member.member.service;

import com.back.domain.member.member.entity.Member;
import com.back.domain.member.member.service.AuthTokenService;
import com.back.domain.member.member.service.MemberService;
import com.back.standard.util.Ut;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class AuthTokenServiceTest {
    @Autowired
    private MemberService memberService;
    @Autowired
    private AuthTokenService authTokenService;
    private int expireSeconds = 60 * 60 * 24 * 365;
    private String secret = "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrstuvwxyz1234567890";

    @Test
    @DisplayName("authTokenService 서비스가 존재한다.")
    void t1() {
        assertThat(authTokenService).isNotNull();
    }

    @Test
    @DisplayName("jjwt 최신 방식으로 JWT 생성, {name=\"Paul\", age=23}")
    void t2() {
        // 토큰 만료기간: 1년
        long expireMillis = 1000L * expireSeconds;

        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        SecretKey secretKey = Keys.hmacShaKeyFor(keyBytes);

        // 발행 시간과 만료 시간 설정
        Date issuedAt = new Date();
        Date expiration = new Date(issuedAt.getTime() + expireMillis);

        String jwt = Jwts.builder()
                .claims(Map.of("name", "Paul", "age", 23)) // 내용
                .issuedAt(issuedAt) // 생성날짜
                .expiration(expiration) // 만료날짜
                .signWith(secretKey) // 키 서명
                .compact();

        assertThat(jwt).isNotBlank();

        System.out.println("jwt = " + jwt);
    }

    @Test
    @DisplayName("Ut.jwt.toString 를 통해서 JWT 생성, {name=\"Paul\", age=23}")
    void t3() {
        String jwt = Ut.jwt.toString(
                secret,
                expireSeconds,
                Map.of("name", "Paul", "age", 23)
        );

        assertThat(jwt).isNotBlank();

        System.out.println("jwt = " + jwt);
    }

    @Test
    @DisplayName("authTokenService.genAccessToken(member);")
    void t4() {
        Member memberUser1 = memberService.findByUsername("user1").get();

        String accessToken = authTokenService.genAccessToken(memberUser1);

        assertThat(accessToken).isNotBlank();

        System.out.println("accessToken = " + accessToken);
    }
}
