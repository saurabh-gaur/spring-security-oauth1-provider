package com.security.oauth

import grails.plugin.springsecurity.SpringSecurityUtils
import grails.transaction.Transactional

import java.security.SecureRandom

import org.apache.commons.codec.binary.Base64
import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.beans.factory.InitializingBean
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.token.Token
import org.springframework.security.core.token.TokenService
import org.springframework.security.oauth.provider.ConsumerDetails
import org.springframework.security.oauth.provider.ConsumerDetailsService
import org.springframework.security.oauth.provider.token.ExpiredOAuthTokenException
import org.springframework.security.oauth.provider.token.InvalidOAuthTokenException
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken
import org.springframework.security.oauth.provider.token.OAuthProviderToken
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices
import org.springframework.security.oauth.provider.token.OAuthTokenLifecycleListener
import org.springframework.security.oauth.provider.token.OAuthTokenLifecycleRegistry
import static com.security.oauth.util.OAuthUtil.*

/**
 * @author Saurabh
 */
@Transactional
class OAuthProviderTokenService implements TokenService, OAuthProviderTokenServices, InitializingBean, OAuthTokenLifecycleRegistry {
	private Random random
	private int requestTokenValiditySeconds = 60 * 10
	private int accessTokenValiditySeconds = 60 * 60 * 12
	private int tokenSecretLengthBytes = 80
	private final Collection<OAuthTokenLifecycleListener> lifecycleListeners = new HashSet<OAuthTokenLifecycleListener>()
	ConsumerDetailsService consumerDetailsService
	GrailsApplication grailsApplication

	//This access token domain class information
	def accessTokenLookup
	def userLookup


	/**
	 * Initialize the token services.
	 * 
	 * @throws Exception
	 * @see {@link RandomValueProviderTokenServices}
	 */
	@Override
	public void afterPropertiesSet() throws Exception {
		if (random == null)
			random = new SecureRandom()
	}

	private Class getOAuthProviderToken() {
		def domainClass = accessTokenLookup.className ? grailsApplication.getDomainClass(accessTokenLookup.className) : null

		if(!domainClass) {
			throw new IllegalArgumentException("The specified access token class '$className' is not a domain class")
		}

		return domainClass.clazz
	}

	private OAuthProviderToken loadByTokenValue(String token) {

		if(!token) {
			throw new IllegalArgumentException("Token is not provided")
		}

		Class oauthProviderToken = getOAuthProviderToken()

		def valuePropertyName = accessTokenLookup.valuePropertyName

		if(!valuePropertyName) {
			throw new IllegalArgumentException("The specified access token property not found")
		}
		return oauthProviderToken.findWhere((valuePropertyName): token)
	}

	/**
	 * @param token
	 */
	@Override
	public OAuthProviderToken getToken(String token) throws AuthenticationException {

		OAuthProviderToken oauthProviderToken = loadByTokenValue(token)

		if (!oauthProviderToken) {
			throw new InvalidOAuthTokenException("Invalid token ${token} ")
		} else if (isExpired(oauthProviderToken)) {
			onTokenRemoved(oauthProviderToken)
			oauthProviderToken.delete(failOnError:true, flush:true)
			throw new ExpiredOAuthTokenException("Expired token.")
		}

		return oauthProviderToken
	}

	/**
	 * Verify if the authentication token is expired
	 * 
	 * @param authToken
	 * @return
	 */
	protected boolean isExpired(OAuthProviderToken authToken) {

		def timestampPropertyName = checkPropertyValueNotNull('timestamp', accessTokenLookup.timestampPropertyName, accessTokenLookup.className)
		def isAccessTokenPropertyName = checkPropertyValueNotNull('isaccesstoken', accessTokenLookup.isAccessTokenPropertyName, accessTokenLookup.className)

		long timestamp = authToken."$timestampPropertyName"

		if (authToken."$isAccessTokenPropertyName") {
			if ((timestamp + (getAccessTokenValiditySeconds() * 1000L)) < System.currentTimeMillis()) {
				return true
			}
		} else {
			if ((timestamp + (getRequestTokenValiditySeconds() * 1000L)) < System.currentTimeMillis()) {
				return true
			}
		}
		return false
	}

	/**
	 * @param consumerKey
	 * @param callbackUrl
	 */
	@Override
	public OAuthProviderToken createUnauthorizedRequestToken(String consumerKey, String callbackUrl) throws AuthenticationException {
		//generate request token
		String tokenValue = UUID.randomUUID().toString()

		//generate secret
		byte[] secretBytes = new byte[getTokenSecretLengthBytes()];
		this.getRandom().nextBytes(secretBytes);
		String secret = new String(Base64.encodeBase64(secretBytes));

		def valuePropertyName = checkPropertyValueNotNull('value', accessTokenLookup.valuePropertyName, accessTokenLookup.className)
		def secretPropertyName = checkPropertyValueNotNull('secret', accessTokenLookup.secretPropertyName, accessTokenLookup.className)
		def callbackUrlPropertyName = checkPropertyValueNotNull('callback URL', accessTokenLookup.callbackUrlPropertyName, accessTokenLookup.className)
		def consumerKeyPropertyName = checkPropertyValueNotNull('consumer key', accessTokenLookup.consumerKeyPropertyName, accessTokenLookup.className)
		def timestampPropertyName = checkPropertyValueNotNull('timestamp', accessTokenLookup.timestampPropertyName, accessTokenLookup.className)
		def isAccessTokenPropertyName = checkPropertyValueNotNull('isaccesstoken', accessTokenLookup.isAccessTokenPropertyName, accessTokenLookup.className)

		//Now load access token domain
		def oauthProviderToken = getOAuthProviderToken().newInstance()

		oauthProviderToken."$valuePropertyName" = tokenValue
		oauthProviderToken."$secretPropertyName" = secret
		oauthProviderToken."$callbackUrlPropertyName" = callbackUrl
		oauthProviderToken."$consumerKeyPropertyName" = consumerKey
		oauthProviderToken."$timestampPropertyName" = System.currentTimeMillis()
		oauthProviderToken."$isAccessTokenPropertyName" = false

		//Now create token
		oauthProviderToken.save(failOnError:true, flush:true)

		//Now listen to create request token
		onTokenCreated(oauthProviderToken)

		return oauthProviderToken
	}

	/**
	 * @param authentication
	 * @return
	 */
	private def getAuthenticatedUser(Authentication authentication) {

		if((authentication == null) || (authentication.isAuthenticated() == false) || (authentication.getPrincipal() == null)) {
			throw new InvalidOAuthTokenException("Invalid authentication")
		}

		//Now find user details to set
		def usernamePropertyName = checkPropertyValueNotNull('username', userLookup.usernamePropertyName, userLookup.userDomainClassName)

		String username = authentication.getPrincipal()."$usernamePropertyName"

		if(username == null) {
			throw new InvalidOAuthTokenException("User not found")
		}

		def userDomainClassName = userLookup.userDomainClassName

		def userDomainClass = userDomainClassName ? grailsApplication.getDomainClass(userDomainClassName) : null

		if(!userDomainClass) {
			throw new IllegalArgumentException("The specified user domain class '$userDomainClassName' is not a domain class")
		}

		return userDomainClass.clazz.findWhere((usernamePropertyName): username)
	}

	/**
	 * @param requestToken
	 * @param verifier
	 * @param authentication
	 */
	public void authorizeRequestToken(String requestToken, String verifier, Authentication authentication) throws AuthenticationException {

		def oauthProviderToken = loadByTokenValue(requestToken)

		if (!oauthProviderToken) {
			throw new InvalidOAuthTokenException("Invalid token ${requestToken}")
		} else if (isExpired(oauthProviderToken)) {
			onTokenRemoved(oauthProviderToken)
			oauthProviderToken.delete(failOnError:true, flush:true)
			throw new ExpiredOAuthTokenException("Expired token.")
		} else if (oauthProviderToken.isAccessToken()) {
			throw new InvalidOAuthTokenException("Request to authorize an access token.")
		}

		def consumerKeyPropertyName = checkPropertyValueNotNull('consumer key', accessTokenLookup.consumerKeyPropertyName, accessTokenLookup.className)
		def userAuthenticationPropertyName = checkPropertyValueNotNull('user authentication', accessTokenLookup.userAuthenticationPropertyName, accessTokenLookup.className)
		def userPropertyName = checkPropertyValueNotNull('user', accessTokenLookup.userPropertyName, accessTokenLookup.className)
		def timestampPropertyName = checkPropertyValueNotNull('timestamp', accessTokenLookup.timestampPropertyName, accessTokenLookup.className)
		def verifierPropertyName = checkPropertyValueNotNull('verifier', accessTokenLookup.verifierPropertyName, accessTokenLookup.className)

		//Now verify current user authorities from consumer authorities
		if(oauthProviderToken."$consumerKeyPropertyName" == null) {
			throw new InvalidOAuthTokenException("Consumer details not found")
		}

		ConsumerDetails details = consumerDetailsService.loadConsumerByConsumerKey(oauthProviderToken."$consumerKeyPropertyName")

		if(!authentication.getAuthorities().containsAll(details.authorities)) {
			throw new InvalidOAuthTokenException("Request token and login user are diffrent")
		}

		oauthProviderToken."$userAuthenticationPropertyName" = authentication
		oauthProviderToken."$userPropertyName" = getAuthenticatedUser(authentication)
		oauthProviderToken."$timestampPropertyName" = System.currentTimeMillis() //reset the expiration.
		oauthProviderToken."$verifierPropertyName" = verifier

		//Now update to authorization verifier
		oauthProviderToken.save(failOnError:true, flush:true)
	}

	/**
	 * @param requestToken
	 */
	public OAuthAccessProviderToken createAccessToken(String requestToken) throws AuthenticationException {

		def oauthProviderToken = loadByTokenValue(requestToken)
		//TODO check for null
		def userPropertyName = accessTokenLookup.userPropertyName

		if (!oauthProviderToken) {
			throw new InvalidOAuthTokenException("Invalid token createAccess : " + requestToken)
		} else if (isExpired(oauthProviderToken)) {
			onTokenRemoved(oauthProviderToken)
			oauthProviderToken.delete(failOnError:true, flush:true)
			throw new ExpiredOAuthTokenException("Expired token.")
		} else if (oauthProviderToken.isAccessToken()) {
			throw new InvalidOAuthTokenException("Not a request token.")
		} else if (!oauthProviderToken."$userPropertyName") {
			throw new InvalidOAuthTokenException("Request token has not been authorized.")
		}

		//Now update request token and secret to access token and secret
		String tokenValue = UUID.randomUUID().toString()

		byte[] secretBytes = new byte[getTokenSecretLengthBytes()]
		this.getRandom().nextBytes(secretBytes);
		String secret = new String(Base64.encodeBase64(secretBytes))

		def valuePropertyName = checkPropertyValueNotNull('value', accessTokenLookup.valuePropertyName, accessTokenLookup.className)
		def secretPropertyName = checkPropertyValueNotNull('secret', accessTokenLookup.secretPropertyName, accessTokenLookup.className)
		def timestampPropertyName = checkPropertyValueNotNull('timestamp', accessTokenLookup.timestampPropertyName, accessTokenLookup.className)
		def isAccessTokenPropertyName = checkPropertyValueNotNull('isaccesstoken', accessTokenLookup.isAccessTokenPropertyName, accessTokenLookup.className)

		oauthProviderToken."$valuePropertyName" = tokenValue
		oauthProviderToken."$secretPropertyName" = secret
		oauthProviderToken."$timestampPropertyName" = System.currentTimeMillis() //reset the expiration.
		oauthProviderToken."$isAccessTokenPropertyName" = true
		oauthProviderToken.save(failOnError:true, flush:true)

		onTokenCreated(oauthProviderToken)

		return oauthProviderToken
	}

	/**
	 * @param token
	 */
	protected void onTokenRemoved(OAuthProviderToken token) {
		for (OAuthTokenLifecycleListener listener : getLifecycleListeners()) {
			listener.tokenExpired(token)
		}
	}

	/**
	 * @param token
	 */
	protected void onTokenCreated(OAuthProviderToken token) {
		for (OAuthTokenLifecycleListener listener : getLifecycleListeners()) {
			listener.tokenCreated(token)
		}
	}

	public int getTokenSecretLengthBytes() {
		return tokenSecretLengthBytes
	}

	/**
	 * The length of the token secret in bytes, before being base64-encoded.
	 * 
	 * @param tokenSecretLengthBytes The length of the token secret in bytes, before being base64-encoded.
	 */
	public void setTokenSecretLengthBytes(int tokenSecretLengthBytes) {
		this.tokenSecretLengthBytes = tokenSecretLengthBytes
	}

	/**
	 * The random value generator used to create token secrets.
	 * 
	 * @return The random value generator used to create token secrets.
	 */
	public Random getRandom() {
		return random
	}

	/**
	 * The random value generator used to create token secrets.
	 * 
	 * @param random The random value generator used to create token secrets.
	 */
	public void setRandom(Random random) {
		this.random = random
	}

	/**
	 * The validity (in seconds) of the unauthenticated request token.
	 * 
	 * @return The validity (in seconds) of the unauthenticated request token.
	 */
	public int getRequestTokenValiditySeconds() {
		return requestTokenValiditySeconds
	}

	/**
	 * The validity (in seconds) of the unauthenticated request token.
	 * 
	 * @param requestTokenValiditySeconds The validity (in seconds) of the unauthenticated request token.
	 */
	public void setRequestTokenValiditySeconds(int requestTokenValiditySeconds) {
		this.requestTokenValiditySeconds = requestTokenValiditySeconds
	}

	/**
	 * The validity (in seconds) of the access token.
	 * 
	 * @return The validity (in seconds) of the access token.
	 */
	public int getAccessTokenValiditySeconds() {
		return accessTokenValiditySeconds
	}

	/**
	 * The validity (in seconds) of the access token.
	 * 
	 * @param accessTokenValiditySeconds The validity (in seconds) of the access token.
	 */
	public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
		this.accessTokenValiditySeconds = accessTokenValiditySeconds
	}

	@Override
	public Collection<OAuthTokenLifecycleListener> getLifecycleListeners() {
		return lifecycleListeners
	}

	@Override
	public void register(OAuthTokenLifecycleListener... lifecycleListeners) {
		if (lifecycleListeners != null)
			this.lifecycleListeners.addAll(Arrays.asList(lifecycleListeners))
	}

	public OAuthProviderToken verifyTokenExists(String token) {
		def oauthProviderToken = loadByTokenValue(token)

		def isAccessTokenPropertyName = checkPropertyValueNotNull('isaccesstoken', accessTokenLookup.isAccessTokenPropertyName, accessTokenLookup.className)

		if (!oauthProviderToken) {
			throw new InvalidOAuthTokenException("Invalid token ${token}")
		} else if (isExpired(oauthProviderToken)) {
			onTokenRemoved(oauthProviderToken)
			oauthProviderToken.delete(failOnError:true, flush:true)
			throw new ExpiredOAuthTokenException("Expired token ${token}")
		} else if (!oauthProviderToken."$isAccessTokenPropertyName") {
			throw new InvalidOAuthTokenException("Request to authorize an access token")
		}
		return oauthProviderToken
	}

	@Override
	public Token allocateToken(String arg0) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Token verifyToken(String token) {
		// TODO Auto-generated method stub
		return null;
	}
}
