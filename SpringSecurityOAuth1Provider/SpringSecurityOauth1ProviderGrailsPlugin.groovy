import grails.plugin.springsecurity.SecurityFilterPosition
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.util.Environment

import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory
import org.springframework.security.oauth.provider.filter.AccessTokenProcessingFilter
import org.springframework.security.oauth.provider.filter.CoreOAuthProviderSupport
import org.springframework.security.oauth.provider.filter.ProtectedResourceProcessingFilter
import org.springframework.security.oauth.provider.filter.UnauthenticatedRequestTokenProcessingFilter
import org.springframework.security.oauth.provider.filter.UserAuthorizationProcessingFilter
import org.springframework.security.oauth.provider.filter.UserAuthorizationSuccessfulAuthenticationHandler
import org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices
import org.springframework.security.oauth.provider.verifier.RandomValueVerifierServices

import com.security.oauth.OAuthConsumerDetailsService
import com.security.oauth.OAuthProviderTokenService
import com.security.oauth.handler.OAuthAuthenticationHandlerWrapper
import com.security.oauth.handler.OAuthFailureAuthenticationHandler
import com.security.oauth.handler.OAuthProcessingFilterEntryPointWrapper
import com.security.oauth.provider.OAuthAuthenticationProviderService

/**
 * @author Saurabh
 */
class SpringSecurityOauth1ProviderGrailsPlugin {
	// the plugin version
	def version = "1.0"
	// the version or versions of Grails the plugin is designed for
	def grailsVersion = "2.5 > *"
	// resources that are excluded from plugin packaging
	def pluginExcludes = ["grails-app/views/error.gsp"]

	// TODO Fill in these fields
	def title = "Spring Security OAuth 1 Provider" // Headline display name of the plugin
	def author = "Saurabh Gaur"
	def authorEmail = "saurabh.gaur@bqurious.com"
	def description = '''\
Spring scurity oauth1 provider
'''

	// URL to the plugin's documentation
	def documentation = "https://saurabh-gaur.github.io/spring-security-oauth1-provider"

	// Extra (optional) plugin metadata

	// License: one of 'APACHE', 'GPL2', 'GPL3'
	//    def license = "APACHE"

	// Details of company behind the plugin (if there is one)
	//    def organization = [ name: "My Company", url: "http://www.my-company.com/" ]

	// Any additional developers beyond the author specified above.
	//    def developers = [ [ name: "Joe Bloggs", email: "joe@bloggs.net" ]]

	// Location of the plugin's issue tracker.
	//    def issueManagement = [ system: "JIRA", url: "http://jira.grails.org/browse/GPMYPLUGIN" ]

	// Online location of the plugin's browseable source code.
	//    def scm = [ url: "http://svn.codehaus.org/grails-plugins/" ]

	def doWithWebDescriptor = { xml ->
		// TODO Implement additions to web.xml (optional), this event occurs before
	}

	def doWithSpring = {

		def conf = SpringSecurityUtils.securityConfig

		if (!conf || !conf.active) {
			return
		}

		println 'Configuring Spring Security OAuth1 provider ...'

		SpringSecurityUtils.loadSecondaryConfig 'DefaultSpringSecurityOAuth1ProviderConfig'
		// have to get again after overlaying DefaultSpringSecurityOAuth1ProviderConfig
		conf = SpringSecurityUtils.securityConfig

		println "... done configuring Spring Security OAuth1 provider"

		//now set providers
		conf.providerNames = ['daoAuthenticationProvider', 'oauthAuthenticationProvider', 'anonymousAuthenticationProvider', 'rememberMeAuthenticationProvider']

		SpringSecurityUtils.registerFilter 'oauthRequestTokenFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 1
		SpringSecurityUtils.registerFilter 'oauthAuthenticateTokenFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 2
		SpringSecurityUtils.registerFilter 'oauthAccessTokenFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 3
		SpringSecurityUtils.registerFilter 'oauthProtectedResourceFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 4

		oauthAuthenticationEntryPoint(OAuthProcessingFilterEntryPointWrapper) {
			realmName = conf.oauthProvider.entryPoint.realmName
		}

		oauthNonceServices(ExpiringTimestampNonceServices) {
			validityWindowSeconds = conf.oauthProvider.nonce.validityWindowSeconds // 12 hrs
		}

		oauthProviderSupport(CoreOAuthProviderSupport) {
			baseUrl = conf.oauthProvider.provider.baseUrl // null
		}

		oauthSignatureMethodFactory(CoreOAuthSignatureMethodFactory) {
			supportPlainText = conf.oauthProvider.signature.supportPlainText // false
			supportHMAC_SHA1 = conf.oauthProvider.signature.supportHMAC_SHA1 // true
			supportRSA_SHA1 = conf.oauthProvider.signature.supportRSA_SHA1  // true
		}

		oauthConsumerDetailsService(OAuthConsumerDetailsService) {
			grailsApplication = ref('grailsApplication')
			consumerLookup = conf.oauthProvider.consumerLookup
		}

		oauthTokenServices(OAuthProviderTokenService) {
			tokenSecretLengthBytes = conf.oauthProvider.tokenServices.tokenSecretLengthBytes // 80
			requestTokenValiditySeconds = conf.oauthProvider.tokenServices.requestTokenValiditySeconds // 10 minutes
			accessTokenValiditySeconds = conf.oauthProvider.tokenServices.accessTokenValiditySeconds // 12 hours
			consumerDetailsService = ref('oauthConsumerDetailsService')
			grailsApplication = ref('grailsApplication')
			accessTokenLookup = conf.oauthProvider.tokenLookup
			userLookup = conf.userLookup
		}

		//init oauthAuthenticationProvider
		oauthAuthenticationProvider(OAuthAuthenticationProviderService) {
			tokenServices = ref('oauthTokenServices')
			accessTokenLookup = conf.oauthProvider.tokenLookup
			userLookup = conf.userLookup
		}

		//init unauthenticatedRequestTokenProcessingFilter
		oauthRequestTokenFilter(UnauthenticatedRequestTokenProcessingFilter) {
			authenticationEntryPoint = ref('oauthAuthenticationEntryPoint')
			nonceServices = ref('oauthNonceServices')
			providerSupport = ref('oauthProviderSupport')
			signatureMethodFactory = ref('oauthSignatureMethodFactory')
			consumerDetailsService = ref('oauthConsumerDetailsService')
			tokenServices = ref('oauthTokenServices')
			filterProcessesUrl = conf.oauthProvider.requestTokenFilter.filterProcessesUrl // '/oauth_request_token'
			ignoreMissingCredentials = conf.oauthProvider.requestTokenFilter.ignoreMissingCredentials // false
			allowedMethods = conf.oauthProvider.requestTokenFilter.allowedMethods // ['GET', 'POST']
			responseContentType = conf.oauthProvider.requestTokenFilter.responseContentType // 'text/plain;charset=utf-8'
			require10a = conf.oauthProvider.require10a // true
		}

		oauthVerifierServices(RandomValueVerifierServices){
			verifierLengthBytes = conf.oauthProvider.verifier.lengthBytes // 6
		}

		oauthSuccessfulAuthenticationHandler(UserAuthorizationSuccessfulAuthenticationHandler) {
			tokenIdParameterName = conf.oauthProvider.successHandler.tokenIdParameterName // 'requestToken'
			callbackParameterName = conf.oauthProvider.successHandler.callbackParameterName // 'callbackURL'
			require10a = conf.oauthProvider.require10a // true
		}

		oauthFailureAuthenticationHandler(OAuthFailureAuthenticationHandler)

		//init userAuthorizationProcessingFilter to verify request token
		oauthAuthenticateTokenFilter(UserAuthorizationProcessingFilter) {
			authenticationManager = ref('authenticationManager')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
			authenticationSuccessHandler = ref('oauthSuccessfulAuthenticationHandler')
			authenticationFailureHandler = ref('oauthFailureAuthenticationHandler')
			rememberMeServices = ref('rememberMeServices')
			authenticationDetailsSource = ref('authenticationDetailsSource')
			filterProcessesUrl = conf.oauthProvider.authTokenFilter.filterProcessesUrl // '/oauth_authenticate_token'
			continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication // false
			allowSessionCreation = conf.apf.allowSessionCreation // true
			require10a = conf.oauthProvider.require10a // true
			tokenIdParameterName = conf.oauthProvider.authTokenFilter.tokenIdParameterName // 'requestToken'
			tokenServices = ref('oauthTokenServices')
			verifierServices = ref('oauthVerifierServices')
		}

		//Init accessTokenProcessingFilter to get access token
		oauthAccessTokenFilter(AccessTokenProcessingFilter) {
			authenticationEntryPoint = ref('oauthAuthenticationEntryPoint')
			nonceServices = ref('oauthNonceServices')
			providerSupport = ref('oauthProviderSupport')
			signatureMethodFactory = ref('oauthSignatureMethodFactory')
			consumerDetailsService = ref('oauthConsumerDetailsService')
			tokenServices = ref('oauthTokenServices')
			ignoreMissingCredentials = conf.oauthProvider.accessTokenFilter.ignoreMissingCredentials // false
			allowedMethods = conf.oauthProvider.accessTokenFilter.allowedMethods // ['GET', 'POST']
			require10a = conf.oauthProvider.require10a // true
			filterProcessesUrl = conf.oauthProvider.accessTokenFilter.filterProcessesUrl // '/oauth_access_token'
		}

		oauthAuthenticationHandler(OAuthAuthenticationHandlerWrapper) { oauthAuthenticationProvider = ref('oauthAuthenticationProvider') }

		//Init protectedResourceProcessingFilter to provide access using oauth1 token credential
		oauthProtectedResourceFilter(ProtectedResourceProcessingFilter) {
			authenticationEntryPoint = ref('oauthAuthenticationEntryPoint')
			nonceServices = ref('oauthNonceServices')
			providerSupport = ref('oauthProviderSupport')
			signatureMethodFactory = ref('oauthSignatureMethodFactory')
			consumerDetailsService = ref('oauthConsumerDetailsService')
			tokenServices = ref('oauthTokenServices')
			authHandler = ref('oauthAuthenticationHandler')
			ignoreMissingCredentials = conf.oauthProvider.protectedResourceFilter.ignoreMissingCredentials // true
			allowAllMethods = conf.oauthProvider.protectedResourceFilter.allowAllMethods // true
		}
	}

	def doWithDynamicMethods = { ctx ->
		// TODO Implement registering dynamic methods to classes (optional)
	}

	def doWithApplicationContext = { ctx ->
		// TODO Implement post initialization spring config (optional)
	}

	def onChange = { event ->
		// TODO Implement code that is executed when any artefact that this plugin is
		// watching is modified and reloaded. The event contains: event.source,
		// event.application, event.manager, event.ctx, and event.plugin.
	}

	def onConfigChange = { event ->
		// The event is the same as for 'onChange'.
	}

	def onShutdown = { event ->
		// TODO Implement code that is executed when the application shuts down (optional)
	}
}
