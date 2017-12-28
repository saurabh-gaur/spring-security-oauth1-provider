package com.security.oauth.provider

import static com.security.oauth.util.OAuthUtil.*
import grails.transaction.Transactional

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.oauth.provider.token.InvalidOAuthTokenException
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices

import com.security.oauth.authentication.OAuthAuthenticationToken

/**
 * Custom authentication provider which will authenticate using token value
 * 
 * @author Saurabh
 */
@Transactional
class OAuthAuthenticationProviderService implements AuthenticationProvider {

	OAuthProviderTokenServices tokenServices
	def accessTokenLookup
	def userLookup


	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		OAuthAuthenticationToken auth = (OAuthAuthenticationToken)authentication
		OAuthAccessProviderToken authToken = tokenServices.getToken(auth.getCredentials())

		def userPropertyName = checkPropertyValueNotNull('user', accessTokenLookup.userPropertyName, accessTokenLookup.className)
		def usernamePropertyName = checkPropertyValueNotNull('username', userLookup.usernamePropertyName, userLookup.userDomainClassName)

		def user = authToken."$userPropertyName"

		if(!user) {
			throw new InvalidOAuthTokenException("Invalid token ${auth.getCredentials()}")
		}

		def username = user."$usernamePropertyName"

		if ((username == null) || (username != auth.getPrincipal()?."$usernamePropertyName")) {
			throw new InvalidOAuthTokenException("Invalid token ${auth.getCredentials()}")
		}
		auth.setAuthenticated(true)
		return auth
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return authentication.isAssignableFrom(OAuthAuthenticationToken.class )
	}

	/**
	 * @param authToken
	 * @param authorities
	 * @return
	 */
	public Authentication createAuthentication(OAuthAccessProviderToken authToken, List<GrantedAuthority> authorities) {

		//Check if proxy session destroy
		//re-attach
		if(!authToken.isAttached()) {
			authToken.attach()
		}

		def valuePropertyName = checkPropertyValueNotNull('value', accessTokenLookup.valuePropertyName, accessTokenLookup.className)
		def userPropertyName = checkPropertyValueNotNull('user', accessTokenLookup.userPropertyName, accessTokenLookup.className)

		return new OAuthAuthenticationToken(authToken."$valuePropertyName",
				authToken."$userPropertyName",
				authorities)
	}
}
