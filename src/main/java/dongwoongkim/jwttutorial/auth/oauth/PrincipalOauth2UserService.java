package dongwoongkim.jwttutorial.auth.oauth;

import dongwoongkim.jwttutorial.auth.PrincipalDetails;
import dongwoongkim.jwttutorial.auth.oauth.provider.GoogleUserInfo;
import dongwoongkim.jwttutorial.auth.oauth.provider.KakaoUserInfo;
import dongwoongkim.jwttutorial.auth.oauth.provider.NaverUserInfo;
import dongwoongkim.jwttutorial.auth.oauth.provider.OAuth2UserInfo;
import dongwoongkim.jwttutorial.entity.User;
import dongwoongkim.jwttutorial.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    // 구글로 부터 받은 userRequest에 대한 후처리 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 만들어짐.
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);
        OAuth2UserInfo oAuth2UserInfo = null;

        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            oAuth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map)oAuth2User.getAttributes().get("response"));
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("kakao")) {
            oAuth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
        } else {
            log.info("지원하지 않는 소셜입니다.");
        }

        Optional<User> userEntity = userRepository.findByProviderAndProviderId(oAuth2UserInfo.getProvider(), oAuth2UserInfo.getProviderId());

        User user;
        if (userEntity.isPresent()) {
            user = userEntity.get();
            user.setEmail(oAuth2UserInfo.getEmail());
            userRepository.save(user);
        } else {
            user = User.builder()
                    .username(oAuth2UserInfo.getProvider() + "_" + oAuth2UserInfo.getProviderId())
                    .email(oAuth2UserInfo.getEmail())
                    .provider(oAuth2UserInfo.getProvider())
                    .providerId(oAuth2UserInfo.getProviderId())
                    .role("ROLE_USER")
                    .build();
            userRepository.save(user);
        }



        return new PrincipalDetails(user, oAuth2User.getAttributes().put("accessToken", userRequest.getAccessToken().getTokenValue()));
    }
}
