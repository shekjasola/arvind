package com.example.demo.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.demo.service.MyUserDetailsService;
import com.example.demo.util.JwtUtil;

@Component
public class JwtFilterRequest extends OncePerRequestFilter
{

	@Autowired
	private MyUserDetailsService service;
	@Autowired
	private JwtUtil jwtutil;
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException
	{
		// TODO Auto-generated method stub
		final String authHeader=request.getHeader("Authorization");
		String username=null;
		String jwt=null;
		if((authHeader!=null)&&(authHeader.startsWith("Bearer")))
		{
			
			 jwt=authHeader.substring(7);
			username=jwtutil.extractUsername(jwt);
		}
		if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null)
		{
			UserDetails userDetails=service.loadUserByUsername(username);
			if(jwtutil.validateToken(jwt, userDetails))
			{
				UsernamePasswordAuthenticationToken authToken=new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
			
		}
		filterChain.doFilter(request,response);
	}

}
