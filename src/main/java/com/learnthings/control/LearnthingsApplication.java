package com.learnthings.control;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan(basePackages={"com.learnthings"})
public class LearnthingsApplication {

	public static void main(String[] args) {
		SpringApplication.run(LearnthingsApplication.class, args);
	}
}
