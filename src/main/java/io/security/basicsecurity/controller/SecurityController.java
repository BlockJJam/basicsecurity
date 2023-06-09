package io.security.basicsecurity.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(){
        return "home";
    }

    @GetMapping("/user")
    public String user(){
        return "user";
    }

//    @GetMapping("/")
//    public String index(HttpSession session) {
//        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//        //session에서도 참조 가능
//        SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
//        Authentication authentication2 = context.getAuthentication();
//
//        return "home";
//    }
//
//    @GetMapping("/thread")
//    public String thread(){
//        new Thread(
//                new Runnable() {
//                    @Override
//                    public void run() {
//                        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//                    }
//                }
//        ).start();
//        return "thread";
//    }
//
//    @GetMapping("/user")
//    public String loginPage() {
//        return "user";
//    }
//
//    @GetMapping("/admin/pay")
//    public String adminPay() {
//        return "adminPay";
//    }
//
//    @GetMapping("admin/**")
//    public String admin() {
//        return "admin";
//    }
//
//    @GetMapping("denied")
//    public String denied(){
//        return "Access is denied";
//    }
//
//    @GetMapping("/login")
//    public String login(){
//        return "login";
//    }
}
