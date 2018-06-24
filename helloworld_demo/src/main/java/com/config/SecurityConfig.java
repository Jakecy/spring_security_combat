package com.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.security.MyLogoutHandler;
@EnableWebSecurity
public class SecurityConfig<MyAuthenticationProvider> extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private MyLogoutHandler  MyLogoutHandler;
	@Autowired
	private MyAuthenticationProvider  MyAuthenticationProvider;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers("/css/**", "/index").permitAll()		
				.antMatchers("/user/**").hasRole("USER")
				.and()
			.formLogin()
				  .loginPage("/static/login.html")
				  .permitAll()
		          .and()
		    .logout()
					.logoutUrl("/my/logout")                                                
					.logoutSuccessUrl("/my/index")                                          
					//.logoutSuccessHandler(MyLogoutHandler)                              
					.invalidateHttpSession(true)                                             
					.addLogoutHandler(MyLogoutHandler)                                         
					.deleteCookies("JSESSIONID")                                       
					.and()
		    .sessionManagement().invalidSessionUrl("/invalidSession.html");//当sessionID无效时的跳转路径
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
			.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER");
		auth.authenticationProvider((AuthenticationProvider) MyAuthenticationProvider);
			    
	}
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
}
