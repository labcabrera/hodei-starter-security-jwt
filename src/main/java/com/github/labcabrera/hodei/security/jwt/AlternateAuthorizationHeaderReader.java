package com.github.labcabrera.hodei.security.jwt;

import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Value;

import lombok.extern.slf4j.Slf4j;

/**
 * Componente encargado de obtener las cabeceras de seguridad de las peticiones cuando se
 * utilizan cabeceras no estandar. Este escenario lo encontrariamos por ejemplo cuando las
 * cabeceras estandar sean utilizadas por otro sistema (generalmente la autenticacion
 * OAuth2 del API Manager) de tal modo que tengamos que utilizar unas propias para que no
 * colisionen.
 * 
 * @author CNP Partners Architecture
 * @since 1.0.0
 */
@Slf4j
public class AlternateAuthorizationHeaderReader implements Function<HttpServletRequest, String> {

	@Value("${app.security.jwt.alternate-header:#{null}}")
	private String alternateHeaderName;

	@Override
	public String apply(HttpServletRequest request) {
		String standardHeader = request.getHeader(JwtConstants.HEADER_AUTHORIZATION);
		String alternateHeader = alternateHeaderName != null ? request.getHeader(alternateHeaderName) : null;

		if (alternateHeader != null) {
			if (standardHeader != null) {
				log.trace("Using alternate authorization header '{}' over standard header '{}'", alternateHeaderName,
					JwtConstants.HEADER_AUTHORIZATION);
			}
			else {
				log.trace("Using alternate authorization header '{}'", alternateHeaderName);
			}
			return alternateHeader;
		}
		else if (standardHeader != null) {
			log.trace("Using standard authorization header '{}'", JwtConstants.HEADER_AUTHORIZATION);
			return standardHeader;
		}
		else {
			log.trace("Undefined Authorization header ({})", request.getServletPath());
			return null;
		}
	}

}
