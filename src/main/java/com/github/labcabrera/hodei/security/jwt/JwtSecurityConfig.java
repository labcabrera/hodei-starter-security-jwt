package com.github.labcabrera.hodei.security.jwt;

import java.util.Arrays;

import javax.servlet.Filter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.github.labcabrera.hodei.security.jwt.filter.JwtAuthenticationFilter;
import com.github.labcabrera.hodei.security.jwt.filter.JwtAuthorizationFilter;

import lombok.extern.slf4j.Slf4j;

/**
 * Comonente para obtener la cabecera de seguridad de una peticion. En primer lugar
 * comprobamos si debemos utilizar una cabecera alternativa. En caso de que no este
 * definida en configuracion o que no este presente utilizamos la cabecera estandar
 * <code>Authorization</code>.
 * 
 * @author CNP Partners Architecture
 * @since 1.0.0
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Slf4j
public class JwtSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment env;

	@Autowired
	private UserDetailsService userDetailsService;

	@Value("${app.security.unsecured.paths:}")
	private String[] unsecuredPaths;

	@Value("${app.security.authentication.path:/token}")
	private String authenticationPath;

	@Value("${app.security.authentication.enabled:true}")
	private Boolean enableAuthentication = true;

	@Value("${app.security.authorization.enabled:true}")
	private Boolean enableAuthorization = true;

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		log.info("Configuring JWT security (authentication: {}, authorization: {})", enableAuthentication, enableAuthorization);
		log.debug("Unsecured paths: {}", Arrays.toString(unsecuredPaths));

		AuthenticationManager authenticationManager = authenticationManager();
		AlternateAuthorizationHeaderReader headerReader = alternateAuthorizationHeaderReader();

		Filter authenticationFilter = null;
		if (enableAuthentication) {
			JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, headerReader, env);
			jwtAuthenticationFilter.setFilterProcessesUrl(authenticationPath);
			authenticationFilter = jwtAuthenticationFilter;
		}
		Filter authorizationFilter = null;
		if (enableAuthorization) {
			authorizationFilter = new JwtAuthorizationFilter(authenticationManager, headerReader, env);
		}

		httpSecurity
			.sessionManagement()
			.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.cors()
			.and()
			.csrf()
			.disable()
			.authorizeRequests()
			.antMatchers(unsecuredPaths).permitAll()
			.anyRequest().authenticated();

		if (authenticationFilter != null) {
			log.debug("Enabling authentication. Path: {}", authenticationPath);
			httpSecurity.addFilter(authenticationFilter);
			httpSecurity.authorizeRequests().antMatchers(HttpMethod.POST, authenticationPath).permitAll();
		}
		if (authorizationFilter != null) {
			log.debug("Enabling authorization");
			httpSecurity.addFilter(authorizationFilter);
		}
	}

	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.debug("Configuring AuthenticationManager");
		auth.userDetailsService(userDetailsService);
	}

	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", new CorsConfiguration().applyPermitDefaultValues());
		return source;
	}

	@Bean
	AlternateAuthorizationHeaderReader alternateAuthorizationHeaderReader() {
		return new AlternateAuthorizationHeaderReader();
	}
}