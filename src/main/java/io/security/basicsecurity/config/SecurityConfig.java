package io.security.basicsecurity.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
//    @Autowired
//    private UserDetailsService userDetailsService;

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user1 = User.withDefaultPasswordEncoder()
                .username("user")
                .password("1111")
                .roles("USER")
                .build();

        UserDetails user2 = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("1111")
                .roles("ADMIN")
                .build();

        UserDetails user3 = User.withDefaultPasswordEncoder()
                .username("sys")
                .password("1111")
                .roles("SYS")
                .build();
        return new InMemoryUserDetailsManager(user1, user2, user3);
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/user/**").hasRole("USER")
                        .requestMatchers("/admin/pay").hasRole("ADMIN")
                        .requestMatchers("/admin/**").access(new WebExpressionAuthorizationManager("hasRole('ADMIN') or hasRole('SYS')"))
                        .anyRequest().authenticated());
//        http.formLogin()
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("usename")
//                .passwordParameter("password")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication" + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception: " + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll();
//
//        http.logout() // POST를 기본 로그아웃 메서드로 활용
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me");
//
//        http.rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);
//
//        http.anonymous();
//        http.sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(false);
        http.formLogin();
        return http.build();
    }
}
