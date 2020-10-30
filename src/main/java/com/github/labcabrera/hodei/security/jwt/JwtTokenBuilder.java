package com.github.labcabrera.hodei.security.jwt;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.List;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Componente encargado de la generacion de tokens JWT.
 * 
 * @author CNP Partners Architecture
 * @since 1.0.0
 */
public class JwtTokenBuilder {

	private String issuer = "cnp-partners";
	private String username;
	private List<String> roles;
	private String secret;
	private int expirationInMinutes = 30;

	public JwtTokenBuilder issuer(String issuer) {
		this.issuer = issuer;
		return this;
	}

	public JwtTokenBuilder userName(String username) {
		this.username = username;
		return this;
	}

	public JwtTokenBuilder roles(List<String> roles) {
		this.roles = roles;
		return this;
	}

	public JwtTokenBuilder secret(String secret) {
		this.secret = secret;
		return this;
	}

	public JwtTokenBuilder expirationInMinutes(int expirationInMinutes) {
		this.expirationInMinutes = expirationInMinutes;
		return this;
	}

	public String build() {
		LocalDateTime now = LocalDateTime.now();
		LocalDateTime expirationDate = now.plusMinutes(expirationInMinutes);
		ZoneId zoneId = ZoneId.systemDefault();
		return Jwts.builder()
			.setIssuedAt(Date.from(now.atZone(zoneId).toInstant()))
			.setExpiration(Date.from(expirationDate.atZone(zoneId).toInstant()))
			.setIssuer(issuer)
			.setSubject(username)
			.claim(JwtConstants.KEY_CLAIM_ROLES, roles)
			.signWith(SignatureAlgorithm.HS512, secret)
			.compact();
	}
}
