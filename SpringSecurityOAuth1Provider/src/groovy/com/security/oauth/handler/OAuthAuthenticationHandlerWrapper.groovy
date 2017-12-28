package com.security.oauth.handler

import javax.servlet.http.HttpServletRequest

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.oauth.provider.ConsumerAuthentication
import org.springframework.security.oauth.provider.OAuthAuthenticationDetails
import org.springframework.security.oauth.provider.OAuthAuthenticationHandler
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken

import com.security.oauth.provider.OAuthAuthenticationProviderService

/**
 * The default authentication handler.
 * 
 * @author Saurabh
 *
 */
class OAuthAuthenticationHandlerWrapper implements OAuthAuthenticationHandler {

	OAuthAuthenticationProviderService oauthAuthenticationProvider

	/**
	 * Default implementation returns the user authentication associated with the auth token, if the token is provided. Otherwise, the consumer authentication
	 * is returned.
	 *
	 * @param request The request that was successfully authenticated.
	 * @param authentication The consumer authentication (details about how the request was authenticated).
	 * @param authToken The OAuth token associated with the authentication. This token MAY be null if no authenticated token was needed to successfully
	 * authenticate the request (for example, in the case of 2-legged OAuth).
	 * @return The authentication.
	 */
	public Authentication createAuthentication(HttpServletRequest request, ConsumerAuthentication authentication, OAuthAccessProviderToken authToken) {
		if (authToken) {

			Authentication userAuthentication = authToken.getUserAuthentication() ?: oauthAuthenticationProvider.createAuthentication(authToken, authentication.getConsumerDetails().getAuthorities())

			if (userAuthentication instanceof AbstractAuthenticationToken) {
				//initialize the details with the consumer that is actually making the request on behalf of the user.
				((AbstractAuthenticationToken) userAuthentication).setDetails(new OAuthAuthenticationDetails(request, authentication.getConsumerDetails()));
			}
			return userAuthentication
		}
		return authentication
	}
}
