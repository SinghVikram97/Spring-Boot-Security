package com.example.demo.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder){
        this.passwordEncoder=passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/","index","/css/*","/js/*").permitAll()
                .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    // Defines how you retrieve your user from db
    protected UserDetailsService userDetailsService() {

        // Create users
        UserDetails myUser = User.builder()
                .username("vikram")
                .password(passwordEncoder.encode("password")) // Must be encoded or will throw error
                .roles(ApplicationUserRole.STUDENT.name()).build(); // ROLE_STUDENT


        UserDetails adminUser = User.builder().username("admin").password(passwordEncoder.encode("admin")).roles(ApplicationUserRole.ADMIN.name()).build(); // ROLE_ADMIN

        UserDetails adminTraineeUser = User.builder().username("trainee").password(passwordEncoder.encode("trainee")).roles(ApplicationUserRole.ADMINTRAINEE.name()).build(); // ROLE_ADMINTRAINEE


        // save users
        return new InMemoryUserDetailsManager(
                myUser,
                adminUser,
                adminTraineeUser
        );
    }
}
