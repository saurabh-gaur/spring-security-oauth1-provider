security {
	oauthProvider {
		require10a = true
		requestTokenFilter {
			filterProcessesUrl = '/oauth_request_token'
			ignoreMissingCredentials = false
			allowedMethods = ['GET', 'POST']
			responseContentType = 'text/plain;charset=utf-8'
		}
		entryPoint { realmName = 'Grails OAuth Provider' // should be changed
		}
		nonce {
			validityWindowSeconds = 60 * 60 * 12 // 12 hrs
		}
		provider { baseUrl = null }
		signature {
			supportPlainText = false
			supportHMAC_SHA1 = true
			supportRSA_SHA1 = true
		}
		tokenServices {
			tokenSecretLengthBytes = 80
			requestTokenValiditySeconds = 60 * 10 //default 10 minutes
			accessTokenValiditySeconds = 60 * 60 * 12 //default 12 hours
		}
		authTokenFilter {
			filterProcessesUrl = '/oauth_authenticate_token'
			tokenIdParameterName = 'requestToken'
		}
		verifier { lengthBytes = 6 }
		successHandler {
			tokenIdParameterName = 'requestToken'
			callbackParameterName = 'callbackURL'
		}
		accessTokenFilter {
			filterProcessesUrl = '/oauth_access_token'
			ignoreMissingCredentials = false
			allowedMethods = ['GET', 'POST']
		}
		protectedResourceFilter {
			allowAllMethods = true
			ignoreMissingCredentials = true
		}

		tokenLookup {
			className = null
			valuePropertyName = 'value'
			secretPropertyName = 'secret'
			callbackUrlPropertyName = 'callbackUrl'
			verifierPropertyName = 'verifier'
			consumerKeyPropertyName = 'consumerKey'
			timestampPropertyName = 'timestamp'
			isAccessTokenPropertyName = 'accessToken'
			userAuthenticationPropertyName = 'userAuthentication'
			userPropertyName = 'user'
		}

		consumerLookup {
			className = null
			consumerKeyPropertyName = 'consumerKey'
			consumerNamePropertyName = 'consumerName'
			consumerSecretPropertyName = 'consumerSecret'
			authoritiesPropertyName = 'authorities'
		}
	}
}