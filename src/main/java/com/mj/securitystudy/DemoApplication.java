package com.mj.securitystudy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ComponentScans;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
@ComponentScans({ @ComponentScan("com.mj.securitystudy.controller"), @ComponentScan("com.mj.securitystudy.config") })
@EnableJpaRepositories("com.mj.securitystudy.repository")
@EntityScan("com.mj.securitystudy.model")
@EnableWebSecurity(debug = true)
public class DemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

}
