package com.learnthings.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;


@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

	private static final String[] BY_PASS_SECURITY_PERMITALL_URLS = { "home", "login" };
	private static final String[] ALLOW_APP_RESOURCES = { "/css/**", "/custom/**", "/images/**", "/fonts/**",
			"/js/**" };

	private static final String WILDCARD = null;

	private CustomAuthenticationProvider customAuthenticationProvider;

	public AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}

	public void configureGlobal(AuthenticationManagerBuilder auth) {
		auth.authenticationProvider(customAuthenticationProvider);
	}

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AjaxTimeoutRedirectFilter ajaxTimeoutRedirectFilter() {
		AjaxTimeoutRedirectFilter ajaxTimeoutRedirectFilter = new AjaxTimeoutRedirectFilter();
		ajaxTimeoutRedirectFilter.setCustomSessionExpiredErrorCode(901);
		return ajaxTimeoutRedirectFilter;

	}

	@Bean
	public CustomAuthenticationSuccessHandler customSuccessHandler() {

		return new CustomAuthenticationSuccessHandler();

	}

	@Bean
	public CustomAuthenticationFailureHandler customAuthenticationFailureHandler() {
		return new CustomAuthenticationFailureHandler();
	}

	@Bean
	public LearnThingsAccessDeniedHandler accessDeniedHandler() {
		LearnThingsAccessDeniedHandler learnThingsaccessDeniedHandler = new LearnThingsAccessDeniedHandler();
		learnThingsaccessDeniedHandler.setAccessDeniedUrl("/denied");
		return new LearnThingsAccessDeniedHandler();
	}

	@Bean
	public SimpleUrlLogoutSuccessHandler simpleUrlLogoutSuccessHandler() {
		SimpleUrlLogoutSuccessHandler successLogoutHAndler = new SimpleUrlLogoutSuccessHandler();
		successLogoutHAndler.setDefaultTargetUrl("/");
		return successLogoutHAndler;

	}

	@Bean
	public SecurityContextLogoutHandler securityContextLogoutHandler() {
		SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
		securityContextLogoutHandler.setInvalidateHttpSession(true);
		securityContextLogoutHandler.setClearAuthentication(true);
		return securityContextLogoutHandler;
	}

	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/resources" + WILDCARD);
	}

	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable().authorizeRequests().antMatchers(BY_PASS_SECURITY_PERMITALL_URLS).permitAll()
				.antMatchers(ALLOW_APP_RESOURCES).permitAll().anyRequest().hasAnyRole("ANONYMOUS, USER")
				.antMatchers("/denied").fullyAuthenticated().anyRequest().authenticated();

		securityFormLogin(http);
	}

	private void securityFormLogin(HttpSecurity http) {
		// TODO Auto-generated method stub

	}
}
