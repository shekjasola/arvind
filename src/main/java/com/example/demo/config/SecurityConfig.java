package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.example.demo.filter.JwtFilterRequest;
import com.example.demo.service.MyUserDetailsService;

@EnableWebSecurity
public class SecurityConfig  extends WebSecurityConfigurerAdapter
{

	@Autowired
	MyUserDetailsService user;
	@Autowired
	JwtFilterRequest req;
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception
	{
		//to provide access for the user
		auth.userDetailsService(user);
	}
	//to skip encoding of password
	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return NoOpPasswordEncoder.getInstance();
	}
	@Override
	protected void configure(HttpSecurity http)throws Exception
	{
		http.csrf().disable().authorizeRequests().antMatchers("/authenticate").permitAll().
		anyRequest().authenticated()
		.and().sessionManagement()
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		http.addFilterBefore(req, UsernamePasswordAuthenticationFilter.class);
	}
	@Bean
	public AuthenticationManager authenticationManagerBean()throws Exception
	{
		return super.authenticationManager();
	}
}
