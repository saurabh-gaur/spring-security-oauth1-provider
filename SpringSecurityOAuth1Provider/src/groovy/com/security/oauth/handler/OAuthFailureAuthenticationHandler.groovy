package com.security.oauth.handler

import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth.provider.token.InvalidOAuthTokenException
import org.springframework.security.web.authentication.AuthenticationFailureHandler

class OAuthFailureAuthenticationHandler implements AuthenticationFailureHandler  {

	private String responseContentType = "text/plain;charset=utf-8";


	@Override
	void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
		int statuscode = HttpServletResponse.SC_UNAUTHORIZED

		if(e instanceof InvalidOAuthTokenException) {
			statuscode = HttpServletResponse.SC_METHOD_NOT_ALLOWED
		}

		httpServletResponse.setContentType(responseContentType)
		httpServletResponse.setStatus(statuscode)
		httpServletResponse.writer.print(e.message)
	}
}
