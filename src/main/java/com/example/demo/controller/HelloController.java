package com.example.demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.demo.model.AuthenticationRequest;
import com.example.demo.model.AuthenticationResponse;
import com.example.demo.service.MyUserDetailsService;
import com.example.demo.util.JwtUtil;

@RestController
public class HelloController {

	
	@Autowired
	private AuthenticationManager authManager;
	@Autowired
	private JwtUtil jwtUtil;
	
	@Autowired
	private MyUserDetailsService service;
	@GetMapping("/hello")
	public String hello()
	{
		return "Hello World";
	}
	@PostMapping("/authenticate")
	public ResponseEntity<?> authenticateUser(@RequestBody AuthenticationRequest req) throws Exception
	{
		try
		{
			authManager.authenticate(new UsernamePasswordAuthenticationToken(req.getUsername(),req.getPassword()));
		}
		catch(Exception e)
		{
			throw new Exception("Incorrect Username and Password",e);
		}
		final UserDetails userDetails=service.loadUserByUsername(req.getUsername());
		final String jwt=jwtUtil.generateToken(userDetails);
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
	}
}
