package com.example.demo.config;

import com.example.demo.config.jwt.JWTConfigurer;
import com.example.demo.config.jwt.TokenProvider;

import org.springframework.beans.factory.config.CustomEditorConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private TokenProvider tokenProvider;
    private PasswordEncoder passwordEncoder;

    public SecurityConfig(TokenProvider tokenProvider, PasswordEncoder passwordEncoder){
        this.tokenProvider = tokenProvider;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
            throws Exception {

    	auth.authenticationProvider(customAuthenticationProvider());
        auth.inMemoryAuthentication()
                .withUser("admin").password(passwordEncoder.encode("adminPass")).authorities("ROLE_ADMIN")
                .and()
                .withUser("user").password(passwordEncoder.encode("userPass")).authorities("ROLE_USER");
    	
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
       http
            .exceptionHandling()
            .authenticationEntryPoint(http401UnauthorizedEntryPoint())
       .and()
           .csrf()
           .disable()
           .headers()
           .frameOptions()
           .disable()
       .and()
           .sessionManagement()
           .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
       .and()
           .authorizeRequests()
           .antMatchers("/api/authenticate").permitAll()
           .antMatchers("/api/user").hasAuthority("ROLE_USER")
           .antMatchers("/api/admin").hasAuthority("ROLE_ADMIN")
           .antMatchers("/api/**").authenticated()
       .and()
            .apply(securityConfigurerAdapter());


    }

    private JWTConfigurer securityConfigurerAdapter() {
        return new JWTConfigurer(tokenProvider);
    }

    
    
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
    	return new CustomAuthenticationProvider();
    }

    //Entry point
    @Bean
    public Http401UnauthorizedEntryPoint http401UnauthorizedEntryPoint() {
        return new Http401UnauthorizedEntryPoint();
    }

    @Bean
    public AuthenticationManager customAuthenticationManager() throws Exception {
        return authenticationManager();
    }

}
