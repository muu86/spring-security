package com.mj.securitystudy.config;

import javax.sql.DataSource;
import org.springframework.cglib.proxy.NoOp;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /*
    /my-account - secured
    /my-balance - secured
    /my-loans   - secured
    /my-cards   - secured

    /notices    - not secured
    /contact    - not secured
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .antMatchers("/my-account").authenticated()
            .antMatchers("/my-balance").authenticated()
            .antMatchers("/my-loans").authenticated()
            .antMatchers("/my-cards").authenticated()
            .antMatchers("/notices").permitAll()
            .antMatchers("/contact").permitAll()
            // deny
            .antMatchers("/deny").denyAll()
            .and()
            .formLogin()
            .and()
            .httpBasic();
    }

    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("admin")
            .password("1234")
            .authorities("admin")
            .and()
            .withUser("user")
            .password("1234")
            .authorities("read")
            .and()
            .passwordEncoder(NoOpPasswordEncoder.getInstance());
    }*/

    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
        UserDetails user1 = User.withUsername("admin").password("1111").authorities("admin")
            .build();
        UserDetails user2 = User.withUsername("user").password("1111").authorities("read").build();
        userDetailsService.createUser(user1);
        userDetailsService.createUser(user2);
        auth.userDetailsService(userDetailsService);
    }*/

    /*@Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }*/

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
