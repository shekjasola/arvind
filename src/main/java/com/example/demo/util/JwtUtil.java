package com.example.demo.util;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JwtUtil {

	private String secretkey="secret";
	
	public String extractUsername(String token)
	{
		return extractClaim(token,Claims::getSubject);
		//getSubject->static ->receive username
	}
	public Date extractExpiration(String token)
	{
		return extractClaim(token,Claims::getExpiration);
		//getExpiration->set/extract the time limit for the token to get expired
	}
	public <T> T extractClaim(String token, Function<Claims,T> claimsResolver)
	{
		final Claims claims=extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	public Claims extractAllClaims(String token)
	{
		return Jwts.parser().setSigningKey(secretkey).parseClaimsJws(token).getBody();
	}
	public Boolean isTokenExpired(String token)
	{
		return extractExpiration(token).before(new Date());
	}
	public String generateToken(UserDetails userdetails)
	{
		Map<String,Object> claims=new HashMap<>();
		return createToken(claims,userdetails.getUsername());
	}
	public String createToken(Map<String,Object> claims, String subject)
	{
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis()+1000*60*60*100))
				.signWith(SignatureAlgorithm.HS256, secretkey).compact();
		//header.payload.signature
	}
	public Boolean validateToken(String token, UserDetails userDetails)
	{
		final String username=extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
}
