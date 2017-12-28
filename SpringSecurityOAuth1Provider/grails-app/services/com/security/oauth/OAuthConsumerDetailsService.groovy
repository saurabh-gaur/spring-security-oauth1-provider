package com.security.oauth

import static org.springframework.security.oauth.common.OAuthCodec.oauthEncode
import grails.plugin.springsecurity.SpringSecurityUtils
import grails.transaction.Transactional

import org.codehaus.groovy.grails.commons.GrailsApplication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.oauth.common.OAuthException
import org.springframework.security.oauth.common.signature.SharedConsumerSecretImpl
import org.springframework.security.oauth.provider.BaseConsumerDetails
import org.springframework.security.oauth.provider.ConsumerDetails
import org.springframework.security.oauth.provider.ConsumerDetailsService
import org.springframework.security.oauth.provider.InvalidOAuthParametersException
import static com.security.oauth.util.OAuthUtil.*

@Transactional
class OAuthConsumerDetailsService implements ConsumerDetailsService {

	GrailsApplication grailsApplication
	def consumerLookup

	@Override
	public ConsumerDetails loadConsumerByConsumerKey(String consumerKey) throws OAuthException {

		if(!consumerKey) {
			throw new IllegalArgumentException("Consumer key is not provided")
		}

		Class consumerClass = getConsumerClass()

		def consumerKeyPropertyName = checkPropertyValueNotNull('consumer key', consumerLookup.consumerKeyPropertyName, consumerLookup.className)

		if(!consumerKeyPropertyName) {
			throw new IllegalArgumentException("The specified consumer key property not found")
		}

		def consumer = consumerClass.findWhere((consumerKeyPropertyName): consumerKey)

		if(!consumer) {
			throw new InvalidOAuthParametersException("Invalid consumer key ${consumerKey} provided")
		}

		return createConsumerDetails(consumer)
	}

	private Class getConsumerClass() {

		def domainClass = consumerLookup.className ? grailsApplication.getDomainClass(consumerLookup.className) : null

		if(!domainClass) {
			throw new IllegalArgumentException("The specified consumer domain class '$consumerLookup.className' is not a domain class")
		}

		return domainClass.clazz
	}

	private ConsumerDetails createConsumerDetails(consumer) {

		def consumerKeyPropertyName = checkPropertyValueNotNull('consumer key', consumerLookup.consumerKeyPropertyName, consumerLookup.className)
		def consumerNamePropertyName = checkPropertyValueNotNull('consumer name', consumerLookup.consumerNamePropertyName, consumerLookup.className)
		def consumerSecretPropertyName = checkPropertyValueNotNull('consumer secret', consumerLookup.consumerSecretPropertyName, consumerLookup.className)
		def authoritiesPropertyName = checkPropertyValueNotNull('authorities', consumerLookup.authoritiesPropertyName, consumerLookup.className)

		return new BaseConsumerDetails
				(authorities:consumer."$authoritiesPropertyName".collect { new SimpleGrantedAuthority(it) },
				consumerKey:consumer."$consumerKeyPropertyName",
				consumerName:consumer."$consumerNamePropertyName",
				signatureSecret:new SharedConsumerSecretImpl(consumer."$consumerSecretPropertyName"))
	}
}
