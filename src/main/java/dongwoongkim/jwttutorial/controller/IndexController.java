package dongwoongkim.jwttutorial.controller;

import dongwoongkim.jwttutorial.auth.PrincipalDetails;
import dongwoongkim.jwttutorial.entity.User;
import dongwoongkim.jwttutorial.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Controller
@RequiredArgsConstructor
public class IndexController {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @GetMapping({"/", ""})
    public String hello() {
        log.info("HI");
        return "index";
    }

    @ResponseBody
    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @ResponseBody
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @ResponseBody
    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/joinForm")
    public String joinForm() {
        return "joinForm";
    }

    @GetMapping("/loginForm")
    public String login() {
        return "loginForm";
    }

    @PostMapping("/join")
    public String join(User user) {
        user.setRole("USER");
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user); // 회원가입 완료. but 시큐리티로 로그인 불가 / (패스워드가 암호화가 되지 않아서)
        log.info("user = {} ", user);
        return "redirect:/loginForm";
    }

    @Secured(value = "ROLE_ADMIN")
    @GetMapping("/info")
    @ResponseBody
    public String info() {
        return "개인정보";
    }

    // 2개 이상 걸고싶을때
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @GetMapping("/data")
    @ResponseBody
    public String data() {
        return "데이터정보";
    }

    // 일반 로그인
    @ResponseBody
    @GetMapping("/test/normal/login")
    public String loginTest(Authentication authentication, @AuthenticationPrincipal UserDetails userDetails) {
        log.info("/test/normal/login ===================");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); // 다운캐스팅 하거나,
        log.info("authentication : {}", principalDetails.getUser());
        log.info("userDetails : {}", userDetails.getUsername()); // 어노테이션으로 하거나
        return "세션 정보 확인하기";
    }

    // OAuth 로그인
    @ResponseBody
    @GetMapping("/test/oauth/login")
    public String loginTestOauth(Authentication authentication, @AuthenticationPrincipal OAuth2User oauth) {
        log.info("/test/oauth/login ===================");
        OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();// 다운캐스팅 하거나,
        log.info("authentication : {}", oAuth2User.getAttributes());
        log.info("oauth2User : {} ", oauth.getAttributes()); // 어노테이션으로 하거나

        return "Oauth 세션 정보 확인하기";
    }

    // 일반 로그인/OAuth 로그인 나누지 않고 상속처리
    // UserDetails -> PrincipalDetails
    // OAuthUser -> PrincipalDetails
    @ResponseBody
    @GetMapping("/test/login")
    public String loginTest(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("/test/login ===================");
        log.info("principalDetails : {}", principalDetails.getUser());
        return "Oauth 또는 일반 로그인 세션 정보 확인하기";
    }


}
