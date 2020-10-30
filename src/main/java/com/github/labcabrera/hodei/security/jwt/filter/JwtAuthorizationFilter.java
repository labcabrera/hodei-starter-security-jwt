package com.github.labcabrera.hodei.security.jwt.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.github.labcabrera.hodei.security.jwt.AlternateAuthorizationHeaderReader;
import com.github.labcabrera.hodei.security.jwt.JwtConstants;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;

/**
 * Filtro de autorizacion que carga el contexto de seguridad a partir del token JWT
 * recibido en la peticion.
 * 
 * @author CNP Partners Architecture
 * @since 1.0.0
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private AlternateAuthorizationHeaderReader headerReader;
	private final String secret;

	public JwtAuthorizationFilter(AuthenticationManager authManager, AlternateAuthorizationHeaderReader headerReader, Environment env) {
		super(authManager);
		this.headerReader = headerReader;
		this.secret = env.getProperty("app.security.jwt.secret");
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.springframework.security.web.authentication.www.BasicAuthenticationFilter
	 * #doFilterInternal(javax.servlet.http.HttpServletRequest,
	 * javax.servlet.http.HttpServletResponse, javax.servlet.FilterChain)
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws IOException, ServletException {
		String header = headerReader.apply(request);
		if (header == null || !header.startsWith(JwtConstants.TOKEN_BEARER_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}
		try {
			UsernamePasswordAuthenticationToken authentication = getAuthentication(request, header);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(request, response);
		}
		catch (SignatureException ex) {
			handleException(ex, response);
		}
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request, String header) {
		log.debug("JWT validation attempt ({} {})", request.getMethod(), request.getRequestURI());
		String token = header.replace(JwtConstants.TOKEN_BEARER_PREFIX, "");
		Jws<Claims> claims;
		try {
			claims = Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
		}
		catch (MalformedJwtException ex) {
			throw new BadCredentialsException(String.format("Malformed Jwt token: '%s'", token));
		}
		String user = claims.getBody().getSubject();
		if (user == null) {
			log.debug("Missing subject in JWT token");
			return null;
		}
		List<GrantedAuthority> grantedAuthorities = readGrantedAuthorities(claims);
		UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(user, null, grantedAuthorities);
		log.debug("Granted authorities: {}", result.getAuthorities());
		Map<String, Object> details = new LinkedHashMap<>();
		details.put("issuer", claims.getBody().getIssuer());
		details.put("expiration", claims.getBody().getExpiration());
		details.put("issuedAt", claims.getBody().getIssuedAt());
		result.setDetails(details);
		return result;
	}

	@SuppressWarnings("unchecked")
	private List<GrantedAuthority> readGrantedAuthorities(Jws<Claims> claims) {
		List<GrantedAuthority> result = new ArrayList<>();
		ArrayList<String> roles = (ArrayList<String>) claims.getBody().get(JwtConstants.KEY_CLAIM_ROLES);
		if (roles != null) {
			roles.forEach(i -> result.add(new SimpleGrantedAuthority(i)));
		}
		return result;
	}

	private void handleException(Exception ex, HttpServletResponse response) {
		log.debug("Invalid JWT token", ex);
		response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	}
}