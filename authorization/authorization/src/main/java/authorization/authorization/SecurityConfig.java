package authorization.authorization;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


private CustomAccessDeniedHandler customAccessDeniedHandler;

        public SecurityConfig(CustomAccessDeniedHandler customAccessDeniedHandler) {
           this.customAccessDeniedHandler = customAccessDeniedHandler;
     }


    @Bean 
    public BCryptPasswordEncoder  passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception   {
        http
                .csrf(csrf -> csrf
                  .csrfTokenRepository(csrfTokenRepository()))

                        .authorizeHttpRequests(auth -> auth
                                        .requestMatchers("/login", "/save","/register","/access-denied").permitAll()
                                        .requestMatchers("/admin/home").hasRole("ADMIN")
                                        .requestMatchers("/user/home").hasRole("USER")
                                        .anyRequest().authenticated()
                        )
                        .formLogin(form -> form
                                        .loginPage("/login")
                                        .defaultSuccessUrl("/default", true)
                                        .permitAll()
                        )
                        .exceptionHandling(exception -> exception
                                       .accessDeniedHandler(customAccessDeniedHandler)
                        )
                        .logout(logout -> logout.logoutSuccessUrl("/login?logout").permitAll());
        return http.build();
    } 



    private CsrfTokenRepository csrfTokenRepository() {
        HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
        repository.setSessionAttributeName("_csrf");
        return repository;
    }


}