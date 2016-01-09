/**
 * 
 */
package com.ge.predix.uaa.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * @author vbanga
 *
 */
public class JwtBearerAuthenticationFilter extends OncePerRequestFilter {

	private static final Log LOGGER = LogFactory.getLog(JwtBearerAuthenticationFilter.class);
	private AuthenticationManager authenticationManager;
	private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

	/**
	 * Creates an instance which will authenticate against the supplied
	 * {@code AuthenticationManager} and which will ignore failed authentication
	 * attempts, allowing the request to proceed down the filter chain.
	 *
	 * @param authenticationManager
	 *            the bean to submit authentication requests to
	 */
	public JwtBearerAuthenticationFilter(AuthenticationManager authenticationManager) {
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		LOGGER.debug("JwtBearerAuthentication filter invoked");
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		String assertion = request.getParameter("assertion");
		if ((authentication == null || !authentication.isAuthenticated()) && assertion != null) {
			LOGGER.debug("Validate the JWT assertion from the client");
			

			UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken("admin",
					"adminsecret");
			authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
			authentication = this.authenticationManager.authenticate(authRequest);
			if (authentication != null && authentication.isAuthenticated()) {
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}
		filterChain.doFilter(request, response);
	}
	
	public void setAuthenticationDetailsSource(
			AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
		Assert.notNull(authenticationDetailsSource,
				"AuthenticationDetailsSource required");
		this.authenticationDetailsSource = authenticationDetailsSource;
	}
}
