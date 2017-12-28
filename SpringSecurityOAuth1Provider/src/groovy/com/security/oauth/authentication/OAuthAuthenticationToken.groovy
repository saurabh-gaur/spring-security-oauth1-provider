package com.security.oauth.authentication

import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.core.authority.SimpleGrantedAuthority

class OAuthAuthenticationToken extends AbstractAuthenticationToken {

	private Object user
	private String token

	public OAuthAuthenticationToken(String token, Object user, Collection<? extends GrantedAuthority> authorities) {
		super(authorities)
		this.user = user
		this.token = token
	}

	@Override
	public Object getCredentials() {
		return token;
	}

	@Override
	public Object getPrincipal() {
		return user;
	}
}
