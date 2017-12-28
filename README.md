# Spring Security OAuth1 Provider

The OAuth1 plugin adds [OAuth 1.0](https://oauth.net/1/) support to a Grails application that uses Spring Security. It depends on [Spring Security Core plugin](http://plugins.grails.org/plugin/grails/spring-security-core).

This documentation specifies a few specific steps you will have to take in order to ensure proper integration with the underlying library.

This plugin provides support for Grails domain classes necessary for providing [OAuth 1.0](https://oauth.net/1/) authorization. Access to protected resources is controlled by a combination of Spring Security Core's methods, i.e. request maps, annotations, intercept maps and careful configuration of the Spring Security filter chains.

# Getting Started

The following assumes that the Spring Security Core plugin has been installed and its required domain class created.

## 1. Install Plugin

Install the OAuth1 plugin by adding a dependency in `grails-app/conf/BuildConfig.groovy`

    plugins {
      compile ":spring-security-oauth1-provider:1.0"
    }
    
### Note :- It's not verified yet by Grails community, hence need to pull this plugin from here directly and compile it locally into your project.

## 2. Create Domain Classes

There is following two domain classes required which needs to be create manually for now 

### 2.1 OAuthConsumer Class

    packaage com.security.oauth

    class OAuthConsumer {
      String consumerKey 
      String consumerName 
      String consumerSecret
      static hasMany = [ authorities: String ]

      static constraints = { 
        consumerKey blank: false, unique: true 
        consumerSecret nullable: true 
        consumerName nullable: true 
        authorities nullable: true 
      }
    }

### 2.2 OAuthAccessProviderTokenWrapper Class

    packaage com.security.oauth

    class OAuthAccessProviderTokenWrapper implements OAuthAccessProviderToken {

      transient userAuthenticationtransient userAuthentication

      String value 
      String callbackUrl 
      String verifier 
      String secret 
      String consumerKey 
      boolean accessToken 
      long timestamp = System.currentTimeMillis()
 
      def user
  
      static transients = ['userAuthentication']

      static constraints = {
         consumerKey blank: false value nullable: true 
         callbackUrl nullable: true 
         verifier nullable: true 
         secret nullable: true 
         timestamp nullable: true 
         user nullable:true 
         userAuthentication nullable:true 
      }
 
      public void setUserAuthentication(Authentication userAuthentication) { 
        this.userAuthentication = userAuthentication; 
      }

      @Override 
      public Authentication getUserAuthentication() { 
        return this.userAuthentication 
      }
    }

Now provided these domains information after adding it in `grails-app/conf/Config.groovy`:

    grails.plugin.springsecurity.oauthProvider.consumerLookup.className = 'com.security.oauth.OAuthConsumer'
    grails.plugin.springsecurity.oauthProvider.tokenLookup.className = 'com.security.oauth.OAuthAccessProviderTokenWrapper'

## 3. Secure Authorization and Token Endpoints

Update the Core plugin's rules for the authorization and token endpoints so they are protected by Spring Security. If you're using the Core plugin's `staticRules`, you'll want to add the following in `grails-app/conf/Config.groovy`:

    grails.plugin.springsecurity.controllerAnnotations.staticRules = [
        '/oauth_request_token'     : ["(request.getMethod().equals('GET') or request.getMethod().equals('POST'))"],
        '/oauth_authenticate_token': ["(request.getMethod().equals('GET') or request.getMethod().equals('POST'))"],
        ...
The endpoints are standard Spring MVC controllers in the underlying Spring Security OAuth1 implementations.

## 4. Exclude `consumer_secret` From Logs

Update the params exclusion list in `grails-app/conf/Config.groovy` so client secrets are not logged in the clear:

    grails.exceptionresolver.params.exclude = ['password', 'consumer_secret']

## 5. Consumer Registration

At this point your application is a proper [OAuth 1.0](https://oauth.net/1/) provider. You can now register consumers in what ever method is appropriate for your application. For example, you can register a consumer in `grails-app/conf/Bootstrap.groovy` as follows:

    def init = { servletContext ->
            new OAuthConsumer
              (consumerKey: 'my-consumer', 
               consumerName : 'Consumer Name', 
               consumerSecret : 'my-secret', 
               authorities : ['ROLE_CLIENT']).save(flush: true, failOnError: true)
     }

## 6. Controlling Access to Resources

Access to resources is controlled by the Spring Security Core plugin's access control mechanisms. Additionally, the plugin has full support for the [OAuth 1.0](https://oauth.net/1/) extensions provided by the underlying Spring library.

    class ConsumerController {

     @Secured('ROLE_CLIENT') 
     def getConsumerInfo() { 
        if(params.oauth_consumer_key) { 
         render "It's oauth1 request" 
        } else { 
         render "it's original login request" 
        } 
      }
    }

The filter chains must be configured to ensure stateless access to the token endpoint and any [OAuth 1.0](https://oauth.net/1/) resources:

    grails.plugin.springsecurity.filterChain.chainMap = [ 
     '/oauth_request_token'      : 'oauthRequestTokenFilter', 
     '/oauth_authenticate_token' : 'securityRequestHolderFilter,securityContextPersistenceFilter,securityContextHolderAwareRequestFilter,rememberMeAuthenticationFilter,exceptionTranslationFilter,filterInvocationInterceptor,oauthAuthenticateTokenFilter',
     '/oauth_access_token'       : 'securityRequestHolderFilter,securityContextPersistenceFilter,oauthAccessTokenFilter', 
     '/consumer/**'              : 'securityRequestHolderFilter,securityContextPersistenceFilter,oauthProtectedResourceFilter,rememberMeAuthenticationFilter,anonymousAuthenticationFilter,exceptionTranslationFilter,filterInvocationInterceptor',
     '/**'                       : 'JOINED_FILTERS'
    ]

# Domain Class Properties

No default class name is assumed for the required domain classes. They must be specified in `grails-app/conf/Config.groovy` as follows :

    grails.plugin.springsecurity.oauthProvider.consumerLookup.className = 'com.security.oauth.OAuthConsumer'
    grails.plugin.springsecurity.oauthProvider.tokenLookup.className = 'com.security.oauth.OAuthAccessProviderTokenWrapper'

The following properties exist in the `grails.plugin.springsecurity.oauthProvider` namespace.

## 1. OAuthConsumer Class Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.4683%;"><col style="width: 24.5868%;"><col style="width: 39.9449%;"></colgroup><thead class="tableFloatingHeaderOriginal" style="position: static; margin-top: 0px; left: 354px; z-index: 3; width: 1148px; top: 77px;"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none; min-width: 8px; max-width: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none; min-width: 8px; max-width: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none; min-width: 8px; max-width: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">consumerLookup.className</td><td class="confluenceTd"><code>null</code></td><td class="confluenceTd">Consumer class name.</td></tr><tr role="row"><td class="confluenceTd">consumerLookup.consumerKeyPropertyName</td><td class="confluenceTd">consumerKey</td><td class="confluenceTd">Consumer class consumer key field.</td></tr><tr role="row"><td class="confluenceTd">consumerLookup.consumerNamePropertyName</td><td class="confluenceTd">consumerName</td><td class="confluenceTd">Consumer class consumer name field.</td></tr><tr role="row"><td class="confluenceTd">consumerLookup.consumerSecretPropertyName</td><td class="confluenceTd">consumerSecret</td><td class="confluenceTd"><p>Consumer class consumer secret field.</p></td></tr><tr role="row"><td colspan="1" class="confluenceTd">consumerLookup.authoritiesPropertyName</td><td colspan="1" class="confluenceTd">authorities</td><td colspan="1" class="confluenceTd">Consumer class authorities field.</td></tr></tbody></table>

## 2. OAuthAccessProviderTokenWrapper Class Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal" style="position: static; margin-top: 0px; left: 354px; z-index: 3; width: 1148px; top: 0px;"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerAsc tablesorter-headerSortUp" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="ascending" aria-label="Property: Ascending sort applied, activate to apply a descending sort" style="user-select: none; min-width: 8px; max-width: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none; min-width: 8px; max-width: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none; min-width: 8px; max-width: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">tokenLookup.callbackUrlPropertyName</td><td class="confluenceTd">callbackUrl</td><td class="confluenceTd"><p>AccessProviderToken class call back URL field.</p></td></tr><tr role="row"><td class="confluenceTd">tokenLookup.className</td><td class="confluenceTd"><code>null</code></td><td class="confluenceTd">AccessProviderToken class name.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">tokenLookup.consumerKeyPropertyName</td><td colspan="1" class="confluenceTd">consumerKey</td><td colspan="1" class="confluenceTd">AccessProviderToken class consumer key field.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">tokenLookup.isAccessTokenPropertyName</td><td colspan="1" class="confluenceTd">accessToken</td><td colspan="1" class="confluenceTd">AccessProviderToken class to check accesstoken field</td></tr><tr role="row"><td class="confluenceTd">tokenLookup.secretPropertyName</td><td class="confluenceTd">secret</td><td class="confluenceTd">AccessProviderToken class secret field.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">tokenLookup.timestampPropertyName</td><td colspan="1" class="confluenceTd">timestamp</td><td colspan="1" class="confluenceTd">AccessProviderToken class timestamp field.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">tokenLookup.userAuthenticationPropertyName</td><td colspan="1" class="confluenceTd">userAuthentication</td><td colspan="1" class="confluenceTd">AccessProviderToken class user authentication field.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">tokenLookup.userPropertyName</td><td colspan="1" class="confluenceTd">user</td><td colspan="1" class="confluenceTd">AccessProviderToken class user field.</td></tr><tr role="row"><td class="confluenceTd">tokenLookup.valuePropertyName</td><td class="confluenceTd">value</td><td class="confluenceTd">AccessProviderToken class value field.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">tokenLookup.verifierPropertyName</td><td colspan="1" class="confluenceTd">verifier</td><td colspan="1" class="confluenceTd">AccessProviderToken class verifier field.</td></tr></tbody></table>

# Other Configuration

The plugin is pessimistic by default, locking down as much as possible to guard against accidental security breaches. However, these constraints can be modified if so desired in `grails-app/conf/Config.groovy`. The properties below exist in the `grails.plugin.springsecurity.oauthProvider` namespace.

The following properties exist in the grails.plugin.springsecurity.oauthProvider namespace :

## 1. Enable Oauth1.0 Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerAsc tablesorter-headerSortUp" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="ascending" aria-label="Property: Ascending sort applied, activate to apply a descending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">require10a</td><td class="confluenceTd"><code>true</code></td><td class="confluenceTd">To enable oauth1.0.</td></tr></tbody></table>

## 2. RequestTokenFilter Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">requestTokenFilter.filterProcessesUrl</td><td class="confluenceTd">/oauth_request_token</td><td class="confluenceTd">End point url for request token.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">requestTokenFilter.ignoreMissingCredentials</td><td colspan="1" class="confluenceTd">false</td><td colspan="1" class="confluenceTd">Ignore missing credential for request token flag.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">requestTokenFilter.allowedMethods</td><td colspan="1" class="confluenceTd">['GET', 'POST']</td><td colspan="1" class="confluenceTd">Methods to support for request.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">requestTokenFilter.responseContentType</td><td colspan="1" class="confluenceTd">text/plain;charset=utf-8</td><td colspan="1" class="confluenceTd">Response content type to parse.</td></tr></tbody></table>

## 3. Endpoint Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">entryPoint.realmName</td><td class="confluenceTd">Grails OAuth Provider</td><td class="confluenceTd">Resposne end point handler realm.</td></tr></tbody></table>

## 4. Nonce Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">nonce.validityWindowSeconds</td><td class="confluenceTd">60 * 60 * 12</td><td class="confluenceTd">Validitiy period of nonce.</td></tr></tbody></table>

## 5. Oauth1.0 Provider Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">provider.baseUrl</td><td class="confluenceTd"><code>null</code></td><td class="confluenceTd">Provider base URL.</td></tr></tbody></table>

## 6. Signature Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">signature.supportPlainText</td><td class="confluenceTd"><code>false</code></td><td class="confluenceTd">Support plain text.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">signature.supportHMAC_SHA1</td><td colspan="1" class="confluenceTd">true</td><td colspan="1" class="confluenceTd">Support HMAC_SHA1 signature method.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">signature.supportRSA_SHA1</td><td colspan="1" class="confluenceTd">true</td><td colspan="1" class="confluenceTd">Support RSA_SHA1 signature method.</td></tr></tbody></table>

## 7. TokenServices Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerAsc tablesorter-headerSortUp" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="ascending" aria-label="Property: Ascending sort applied, activate to apply a descending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td colspan="1" class="confluenceTd">tokenServices.accessTokenValiditySeconds</td><td colspan="1" class="confluenceTd">60 * 60 * 12</td><td colspan="1" class="confluenceTd">Acess token validity period.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">tokenServices.requestTokenValiditySeconds</td><td colspan="1" class="confluenceTd">60 * 10</td><td colspan="1" class="confluenceTd">Request token validity period.</td></tr><tr role="row"><td class="confluenceTd">tokenServices.tokenSecretLengthBytes</td><td class="confluenceTd">80</td><td class="confluenceTd">Token secret length.</td></tr></tbody></table>

## 8. AuthTokenFilter Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">authTokenFilter.filterProcessesUrl</td><td class="confluenceTd">/oauth_authenticate_token</td><td class="confluenceTd">End point URL to authorize token.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">authTokenFilter.tokenIdParameterName</td><td colspan="1" class="confluenceTd">requestToken</td><td colspan="1" class="confluenceTd">Parameter name to get request token for authorization.</td></tr></tbody></table>

## 9. Requiest token verifier Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">verifier.lengthBytes</td><td class="confluenceTd"><code>6</code></td><td class="confluenceTd">Length of verifier request token.</td></tr></tbody></table>

## 10. SuccessHandler Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">successHandler.tokenIdParameterName</td><td class="confluenceTd">requestToken</td><td class="confluenceTd">Response token parameter name.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">successHandler.callbackParameterName</td><td colspan="1" class="confluenceTd">callbackURL</td><td colspan="1" class="confluenceTd">Response callback URL parameter name.</td></tr></tbody></table>

## 11. AccessTokenFilter Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">accessTokenFilter.filterProcessesUrl</td><td class="confluenceTd">/oauth_access_token</td><td class="confluenceTd">End point URL to obtain acesstoken.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">accessTokenFilter.ignoreMissingCredentials</td><td colspan="1" class="confluenceTd">false</td><td colspan="1" class="confluenceTd">Ignore missing credetial to obtain accesstoken flag.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">accessTokenFilter.allowedMethods</td><td colspan="1" class="confluenceTd">['GET', 'POST']</td><td colspan="1" class="confluenceTd">Methods to support forobtain accesstoken.</td></tr></tbody></table>

## 12. ProtectedResourceFilter Properties

<table class="relative-table wrapped confluenceTable tablesorter tablesorter-default stickyTableHeaders" style="width: 96.6733%; padding: 0px;" role="grid" resolved=""><colgroup><col style="width: 35.1928%;"><col style="width: 24.9311%;"><col style="width: 39.876%;"></colgroup><thead class="tableFloatingHeaderOriginal"><tr role="row" class="tablesorter-headerRow"><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="0" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Property: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Property</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="1" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Default Value: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Default Value</strong></div></th><th class="confluenceTh tablesorter-header sortableHeader tablesorter-headerUnSorted" data-column="2" tabindex="0" scope="col" role="columnheader" aria-disabled="false" unselectable="on" aria-sort="none" aria-label="Meaning: No sort applied, activate to apply an ascending sort" style="user-select: none;"><div class="tablesorter-header-inner"><strong class="bold">Meaning</strong></div></th></tr></thead><tbody aria-live="polite" aria-relevant="all"><tr role="row"><td class="confluenceTd">protectedResourceFilter.allowAllMethods</td><td class="confluenceTd"><code>true</code></td><td class="confluenceTd">Allow all methods flag.</td></tr><tr role="row"><td colspan="1" class="confluenceTd">protectedResourceFilter.ignoreMissingCredentials</td><td colspan="1" class="confluenceTd">true</td><td colspan="1" class="confluenceTd">Ignore missing credetial to acess resources flag.</td></tr></tbody></table>

# Example Flows

The key to understanding how OAuth1 works is understanding the authorization flow. This is the process clients go through to link to a site.

The flow with the OAuth1 plugin is called the **three-legged** flow, thanks to the three primary steps involved:

Temporary Credentials Acquisition: The client gets a set of temporary credentials from the server.
Authorization: The user "authorizes" the request token to access their account.
Token Exchange: The client exchanges the short-lived temporary credentials for a long-lived token.

## 1. Temporary Credentials Acquisition
The first step to authorization is acquiring temporary credentials (also known as a Request Token). These credentials are short-lived (typically 24 hours), and are used purely for the initial authorization process. They don't grant any access to data on the server, and cannot be used for anything except the authorization flow.

These credentials are acquired by an initial HTTP request to the server. The client starts by sending a POST request to the temporary credential URL, typically `/oauth_request_token` with the plugin. (This URL should be autodiscovered from the API, as individual sites may move this route, or delegate the process to another server.) This looks something like:

This request includes the client key (`oauth_consumer_key`), the authorization callback (`oauth_callback`), and the request signature (`oauth_signature` and `oauth_signature_method`). This looks something like:

    POST /oauth_request_token HTTP/1.1
    Host: http://localhost:8080
    Authorization: OAuth realm="Example",
               oauth_consumer_key="my-consumer",
               oauth_signature_method="HMAC-SHA1",
               oauth_timestamp="1513678344",
               oauth_nonce="Dc85Pk",
               oauth_version=1.0,
               oauth_callback="http://localhost:8080/token",
               oauth_signature="zCVppwQZ0Y7T68gxPLFzaMObhks="

Note : You can directlly hit the following URL on browser for getting the same :

http://localhost:8080/oauth_request_token?oauth_consumer_key=my-consumer&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1513678344&oauth_nonce=Dc85Pk&oauth_version=1.0&oauth_signature=zCVppwQZ0Y7T68gxPLFzaMObhks=&oauth_callback=http://localhost:8080/token

The server checks the key and signature to ensure the client is valid. It also checks the callback to ensure it's valid for the client.

Once the checks are complete, the server creates a new set of Temporary Credentials (`oauth_token` and `oauth_token_secret`) and returns them in the HTTP response (URL encoded). This looks something like:

    HTTP/1.1 200 OK
    Content-Type: application/x-www-form-urlencoded

    oauth_token=hdk48Djdsa&oauth_token_secret=xyz4992k83j47x0b&oauth_callback_confirmed=true

These credentials are then used as the oauth_token and oauth_token_secret parameters for the Authorization and Token Exchange steps.

Note : The `oauth_callback_confirmed=true` will always be returned, and indicates that the protocol is [OAuth 1.0](https://oauth.net/1/).

## 2 Authorization
The next step in the flow is the authorization process. This is a user-facing step, and the one that most users will be familiar with.

Using the authorization URL supplied by the site (typically `/oauth_authenticate_token`), the client appends the temporary credential key (`requestToken` from above) to the URL as a query parameter (again as `requestToken` ). The client then directs the user to this URL. Typically, this is done via a redirect for in-browser clients, or opening a browser for native clients.

The user then logs in if they aren't already, and authorizes the client. They can also choose to cancel the authorization process if they don't want to link the client.

If the user authorizes the client, the site then marks the token as authorized, and redirects the user back to the callback URL. The callback URL includes two extra query parameters: `oauth_token` (the same temporary credential token) and `oauth_verifier`, a CSRF token that needs to be passed in the next step.

For eg. http://localhost:8080/token?oauth_token=b9c91204-e4c3-42b3-a479-b85dff86427d&oauth_verifier=uVA2W3 where  http://localhost:8080/token is redirect URL

## 3. Token Exchange
The final step in authorization is to exchange the temporary credentials (request token) for long-lived credentials (also known as an Access Token). This request also destroys the temporary credentials.

The temporary credentials are converted to long-lived credentials by sending a POST request to the token request endpoint (typically `/oauth_authenticate_token`). This request must be signed by the temporary credentials, and must include the oauth_verifier token from the authorization step. The request looks something like:

    POST /oauth_authenticate_token HTTP/1.1
    Host: http://localhost:8080 
    Authorization: OAuth realm="Example",
         oauth_consumer_key="my-consumer",
         oauth_token="hdk48Djdsa",
         oauth_signature_method="HMAC-SHA1",
         oauth_timestamp="1513668573",
         oauth_nonce="8JpkZv", oauth_verifier="uVA2W3",
         oauth_version=1.0,
         oauth_signature="/133b9TEIp3f9l3W5hZVgEOyTYA="

Note : You can directly hit the following URL on browser for getting the same :

http://localhost:8080/oauth_access_token?oauth_consumer_key=my-consumer&oauth_token=b9c91204-e4c3-42b3-a479-b85dff86427d&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1513668573&oauth_nonce=8JpkZv&oauth_version=1.0&oauth_signature=/133b9TEIp3f9l3W5hZVgEOyTYA=&oauth_verifier=uVA2W3

The server again checks the key and signature, as well as also checking the verifier token to [avoid CSRF attacks](http://oauth.net/advisories/2009-1/).

Assuming these checks all pass, the server will respond with the final set of credentials in the HTTP response body (form data, URL-encoded):

    HTTP/1.1 200 OK
    Content-Type: application/x-www-form-urlencoded

    oauth_token=j49ddk933skd9dks&oauth_token_secret=ll399dj47dskfjdk

At this point, you can now discard the temporary credentials (as they are now useless), as well as the verifier token.
