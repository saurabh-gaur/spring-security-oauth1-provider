package com.security.oauth.handler

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth.common.signature.UnsupportedSignatureMethodException
import org.springframework.security.oauth.provider.InvalidOAuthParametersException
import org.springframework.security.oauth.provider.OAuthProcessingFilterEntryPoint
import org.springframework.security.web.AuthenticationEntryPoint

class OAuthProcessingFilterEntryPointWrapper extends OAuthProcessingFilterEntryPoint {

	private String responseContentType = "text/plain;charset=utf-8";

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

		if (authException instanceof InvalidOAuthParametersException) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST)
		}
		else if (authException.getCause() instanceof UnsupportedSignatureMethodException) {
			response.setStatus(HttpServletResponse.SC_BAD_REQUEST)
		}
		else {
			StringBuilder headerValue = new StringBuilder("OAuth")
			if (realmName) {
				headerValue.append(" realm=\"").append(realmName).append('"')
			}
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED)
			response.addHeader("WWW-Authenticate", headerValue.toString())
		}
		response.setContentType(responseContentType)
		response.writer.print(authException.getMessage())
	}
}
