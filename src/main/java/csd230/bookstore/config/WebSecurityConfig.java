package csd230.bookstore.config;

import csd230.bookstore.auth.JwtAuthorizationFilter;
import csd230.bookstore.services.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    private final CustomUserDetailsService userDetailsService;
    private final JwtAuthorizationFilter jwtAuthorizationFilter;

    public WebSecurityConfig(CustomUserDetailsService userDetailsService,
                             JwtAuthorizationFilter jwtAuthorizationFilter) {
        this.userDetailsService = userDetailsService;
        this.jwtAuthorizationFilter = jwtAuthorizationFilter;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(requests -> requests

                        // 1. Public resources
                        .requestMatchers("/h2-console/**", "/login", "/css/**", "/js/**", "/error").permitAll()
                        .requestMatchers("/api/rest/auth/**").permitAll()

                        // 2. Swagger docs
                        .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html").permitAll()

                        // 3. CPU endpoints — GET for any authenticated user, mutating for ADMIN only
                        .requestMatchers(HttpMethod.GET,    "/api/rest/cpus/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST,   "/api/rest/cpus/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT,    "/api/rest/cpus/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/rest/cpus/**").hasRole("ADMIN")

                        // 4. GPU endpoints — GET for any authenticated user, mutating for ADMIN only
                        .requestMatchers(HttpMethod.GET,    "/api/rest/gpus/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers(HttpMethod.POST,   "/api/rest/gpus/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT,    "/api/rest/gpus/**").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/api/rest/gpus/**").hasRole("ADMIN")

                        // 5. All other REST endpoints — any authenticated role
                        .requestMatchers("/api/rest/**").hasAnyRole("USER", "ADMIN")

                        // 6. Web UI Admin actions
                        .requestMatchers("/books/add", "/books/edit/**", "/books/delete/**").hasRole("ADMIN")

                        // 7. Everything else requires authentication — MUST be last
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, authException) -> {
                            if (request.getRequestURI().startsWith("/api/rest/")) {
                                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                            } else {
                                response.sendRedirect("/login");
                            }
                        })
                )
                .addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/books", true)
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );

        http.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**", "/api/rest/**"));

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }
}