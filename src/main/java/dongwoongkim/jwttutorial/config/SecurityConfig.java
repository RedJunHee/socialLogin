package dongwoongkim.jwttutorial.config;

import dongwoongkim.jwttutorial.auth.PrincipalDetailsService;
import dongwoongkim.jwttutorial.auth.oauth.CustomSuccessHandler;
import dongwoongkim.jwttutorial.auth.oauth.PrincipalOauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
/**
 * 구글 로그인이 완료된 이후 후처리(세션) 필요
 * Tip. 코드 X ( 액세스토큰 + 사용자프로필정보 O)
 * 1. 코드받기(인증)
 * 2. 액세스토큰(인가)
 * 3. 사용자 프로필 정보를 가져와서
 * 4. 그 정보를 토대로 회원가입 하거나
 * 4. 그 정보 + 추가정보 요구
 */

@Configuration
@EnableGlobalMethodSecurity(securedEnabled = true, // @Secured 활성화
                            prePostEnabled = true // @PreAuthorized 활성화, @PostAuthroized 활성화
)
public class SecurityConfig {
    @Autowired
    PrincipalOauth2UserService principalOauth2UserService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/user/**").authenticated() // 인증
                .antMatchers("/manager/**").access("hasRole('ROLE_ADMIN') or hasRole('ROLE_MANAGER')") // 인증 + 인가
                .antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')") // 인증 + 인가
                .anyRequest().permitAll()

                .and()
                //demo이기에 폼 로그인 설정
                .formLogin()
                // 폼 로그인 화면 설정.
                .loginPage("/loginForm")
                .loginProcessingUrl("/login") // login 주소가 호출이되면 시큐리티가 낚아채서 대신 로그인 진행해줌.
                .defaultSuccessUrl("/")

                .and()
                .oauth2Login()
                .loginPage("/loginForm")
                .userInfoEndpoint()
                .userService(principalOauth2UserService);
                //.and()
                //.successHandler(customSuccessHandler()); // 구글 로그인 이후 후처리


        return http.build();
    }

    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return new CustomSuccessHandler();
    }

}
