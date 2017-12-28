package com.security.oauth.util

/**
 * @author Saurabh
 */
class OAuthUtil {


	public static def checkPropertyValueNotNull(String propertyName, String propertyValue, String className) {

		if(!propertyValue) {
			throw new IllegalArgumentException("The specified ${propertyName} property is not define for '$className' domain class")
		}
		return propertyValue
	}
}
