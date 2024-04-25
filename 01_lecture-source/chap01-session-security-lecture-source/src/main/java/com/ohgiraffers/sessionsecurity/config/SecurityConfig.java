package com.ohgiraffers.sessionsecurity.config;

import com.ohgiraffers.sessionsecurity.common.UserRole;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
/* spring security 의 기능을 활성화 시키는 어노테이션 */
public class SecurityConfig {

    /* 필기.
    *   비밀번호를 인코딩 하기 위한 Bean
    *   Bcrypt : 비밀번호 해싱에 가장 많이 사용되고 있는 알고리즘.
    *  */
    /* 필기.
    *   1. 보안성 : 해시 함수에 무작위 솔트를 적용하여 생성해준다.
    *   2. 호환성 : 높은 보안 수준 및 데이터베이스에 저장하기 쉬운 특징
    *   3. 알고리즘 신뢰성 : 보안에 논의 평가를 거친 알고리즘으로 문제 없이 사용 가능
    *  */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /* 필기.
    *   정적인 리소스에 대한 요청을 제외하는 설정을 하는 bean
    *  */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring()
                .requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain configure(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests( auth -> {
            auth.requestMatchers("/auth/login", "/user/signup", "/auth/fail", "/", "/main").permitAll();
            auth.requestMatchers("/admin/*").hasAnyAuthority(UserRole.ADMIN.getRole());
            auth.requestMatchers("/user/*").hasAnyAuthority(UserRole.USER.getRole());
            auth.anyRequest().authenticated();
        })
    }

}
