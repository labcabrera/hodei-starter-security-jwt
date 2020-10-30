package com.github.labcabrera.hodei.security.jwt.filter;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.Assert;

import com.github.labcabrera.hodei.security.jwt.AlternateAuthorizationHeaderReader;
import com.github.labcabrera.hodei.security.jwt.JwtConstants;
import com.github.labcabrera.hodei.security.jwt.JwtTokenBuilder;

import lombok.extern.slf4j.Slf4j;

/**
 * Filtro de autenticacion de Hodei que genera el token JWT a partir de las cabeceras de
 * seguridad basica.
 * 
 * @author CNP Partners Architecture
 * @since 1.0.0
 */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private static final String SUCCESS_RESPONSE_TEMPLATE = "{\"token_type\":\"Bearer\",\"access_token\":\"%s\"}";

	private final AuthenticationManager authenticationManager;
	private final AlternateAuthorizationHeaderReader headerReader;
	private final Integer expiration;
	private final String secret;
	private final String issuer;

	public JwtAuthenticationFilter(
		AuthenticationManager authenticationManager,
		AlternateAuthorizationHeaderReader headerReader,
		Environment env) {
		this.authenticationManager = authenticationManager;
		this.headerReader = headerReader;
		this.expiration = env.getProperty("app.security.jwt.expiration", Integer.class);
		this.secret = env.getProperty("app.security.jwt.secret");
		this.issuer = env.getProperty("spring.application.name");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.web.authentication.
	 * UsernamePasswordAuthenticationFilter#attemptAuthentication(javax.servlet.
	 * http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
		log.debug("Attempting authentication");
		try {
			String header = headerReader.apply(request);
			Assert.isTrue(header.startsWith("Basic "), "Expected Basic Authorization header");
			String b64 = header.replace("Basic ", "");
			String decoded = new String(Base64.getDecoder().decode(b64), Charset.forName("UTF-8"));
			int index = decoded.indexOf(':');
			Assert.isTrue(index > 0, "Invalid credentials");
			String username = decoded.substring(0, index);
			String password = decoded.substring(index + 1, decoded.length());
			UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				username,
				password,
				new ArrayList<>());
			return authenticationManager.authenticate(token);
		}
		catch (AuthenticationException ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new InternalAuthenticationServiceException("Authentication error", ex);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.web.authentication.
	 * AbstractAuthenticationProcessingFilter#successfulAuthentication(javax.
	 * servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse,
	 * javax.servlet.FilterChain, org.springframework.security.core.Authentication)
	 */
	@Override
	protected void successfulAuthentication(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain chain,
		Authentication auth) throws IOException, ServletException {

		String token = createToken(auth);
		log.debug("Success authentication for user {}", auth.getName());
		response.addHeader(JwtConstants.HEADER_AUTHORIZATION, JwtConstants.TOKEN_BEARER_PREFIX + " " + token);
		response.setContentType("application/json");
		response.getWriter().write(String.format(SUCCESS_RESPONSE_TEMPLATE, token));
		response.getWriter().close();
	}

	private String createToken(Authentication auth) {
		String username = ((UserDetails) auth.getPrincipal()).getUsername();
		List<String> roles = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
		return new JwtTokenBuilder()
			.issuer(issuer)
			.userName(username)
			.roles(roles)
			.expirationInMinutes(expiration)
			.secret(secret)
			.build();
	}
}