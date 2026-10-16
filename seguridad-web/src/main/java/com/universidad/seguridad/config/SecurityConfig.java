package com.universidad.seguridad.config;

import com.universidad.seguridad.security.JwtAuthFilter;
import com.universidad.seguridad.service.UsuarioDetailsService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public DaoAuthenticationProvider authProvider(UsuarioDetailsService uds, PasswordEncoder pe) {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(uds);
        p.setPasswordEncoder(pe);
        return p;
    }

    // AuthenticationManager que usa ApiAuthController: el MISMO proveedor
    // (UserDetailsService + BCrypt) que valida el form-login de la Parte 1.
    // Spring Boot no lo expone como bean por defecto, por eso se declara.
    @Bean
    public AuthenticationManager authenticationManager(DaoAuthenticationProvider authProvider) {
        return new ProviderManager(authProvider);
    }

    // JwtAuthFilter es un @Component y Spring Boot registraría por defecto
    // todo Filter como filtro de servlet para TODAS las rutas. Se desactiva
    // ese registro automático para que solo actúe dentro de apiFilterChain.
    @Bean
    public FilterRegistrationBean<JwtAuthFilter> desactivarRegistroGlobalJwt(JwtAuthFilter filtro) {
        FilterRegistrationBean<JwtAuthFilter> registro = new FilterRegistrationBean<>(filtro);
        registro.setEnabled(false);
        return registro;
    }

    @Bean
    @Order(1) // se evalúa ANTES que webFilterChain (@Order(2)): más específico primero
    public SecurityFilterChain apiFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
        http
            .securityMatcher("/api/**") // esta cadena SOLO aplica a /api/**
            // Correcto aquí: no hay cookie de sesión que un atacante pueda
            // aprovechar; el token va en el header Authorization, que un
            // formulario cross-site no puede fijar por sí solo
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            // Sin form-login ni httpBasic, Spring Security respondería 403 a una
            // petición sin token; la API debe responder 401 Unauthorized
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // Cadena de filtros para las vistas web con Thymeleaf — basada en
    // sesión. @Order(2): se evalúa después de apiFilterChain. Sin @Order
    // explícito, Spring Security no garantiza cuál cadena evalúa primero
    // cuando hay más de un SecurityFilterChain.
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/**") // todo lo que no sea /api/**
            .authorizeHttpRequests(auth -> auth
                // /error se permite para que las páginas de error (403, 404)
                // se muestren en vez de redirigir al login
                .requestMatchers("/", "/login", "/registro", "/error",
                                 "/css/**", "/js/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            );
            // CSRF queda ACTIVO (comportamiento por defecto de Spring
            // Security): esta cadena sirve formularios Thymeleaf con
            // cookie de sesión, el escenario exacto que CSRF protege.
        return http.build();
    }
}
