package dongwoongkim.jwttutorial.auth.oauth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;

public class CustomSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
/*
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        // OAuth2AuthenticationToken에서 OAuth2User를 추출
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();

        // OAuth2User에서 authorities를 가져오고, 해당 authorities에서 AccessToken을 추출
        Collection<? extends GrantedAuthority> authorities = oAuth2User.getAuthorities();
        String tokenValue = extractToken(authorities);

        // AccessToken을 추출하여 사용자에게 전달하거나 다른 작업 수행
        // 여기에서 토큰을 사용자에게 전달하는 예제
        // 토큰을 HTTP 응답으로 전달하거나, 사용자 정보와 함께 다른 작업을 수행할 수 있음
        response.getWriter().write("Authentication Successful! Token: " + tokenValue);
        response.getWriter().flush();

        // 부모 클래스의 동작 수행
        super.onAuthenticationSuccess(request, response, authentication);
    }

    private String extractToken(Collection<? extends GrantedAuthority> authorities) {
        for (GrantedAuthority authority : authorities) {
            if (authority instanceof OAuth2UserTokenAuthority) {
                return ((OAuth2UserTokenAuthority) authority).getToken().getTokenValue();
            }
        }
        throw new OAuth2AuthenticationException("No AccessToken found in authorities");
    }*/
}