package com.niee;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.*;

@SpringBootApplication
@RestController
public class SecurityApplication {

	@RequestMapping("/resource")
	@CrossOrigin(allowedHeaders = "*")
	public Map<String,Object> home() {
		Map<String,Object> model = new HashMap<String,Object>();
		model.put("id", UUID.randomUUID().toString());
		model.put("content", "Hello World");
		return model;
	}

	@RequestMapping("/user")
	@CrossOrigin(allowedHeaders = "*")
	public Principal user(Principal user) {
		return user;
	}

	@Configuration
	@Order(SecurityProperties.BASIC_AUTH_ORDER)
	protected static class SecurityConfiguration extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.httpBasic()
					.and()
					.cors()
					.and()
					.authorizeRequests()
					.antMatchers("/index.html", "/", "/home", "/login","/resource").permitAll()
					.anyRequest().hasRole("USER");
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth)
				throws Exception {
			auth.authenticationProvider(authenticationProvider());
		}

		@Bean
		public DaoAuthenticationProvider authenticationProvider() {
			DaoAuthenticationProvider authProvider
					= new DaoAuthenticationProvider();
			authProvider.setUserDetailsService(new UserDetailsService() {

				@Autowired
				private PasswordEncoder passwordEncoder;

				@Override
				public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
					List<GrantedAuthority> grantedAuthorities = new ArrayList<>();
					grantedAuthorities.add(new SimpleGrantedAuthority("ROLE_USER"));
					return new User("niee","$2a$11$2fQRkO8ajQ9KlRrv9ommAOC7h5KaENiGgjoGwCrgqYTE/71tI3vgy",grantedAuthorities);
				}
			});
			authProvider.setPasswordEncoder(encoder());
			return authProvider;
		}

		@Bean
		public PasswordEncoder encoder() {
			return new BCryptPasswordEncoder(11);
		}
	}

	public static void main(String[] args) {
		PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(11);
		System.out.println(passwordEncoder.encode("1234"));
		SpringApplication.run(SecurityApplication.class, args);
	}
}
