/*
 * web: XnatLdapAuthenticationProvider
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnat.auth.ldap.provider;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.xdat.XDAT;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.auth.ldap.tokens.XnatLdapUsernamePasswordAuthenticationToken;
import org.nrg.xnat.security.provider.XnatAuthenticationProvider;
import org.nrg.xnat.security.tokens.XnatAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class XnatLdapAuthenticationProvider extends LdapAuthenticationProvider implements XnatAuthenticationProvider {
    @SuppressWarnings("unused")
    public XnatLdapAuthenticationProvider(final String providerId, final String displayName, final LdapAuthenticator authenticator, final UserDetailsContextMapper contextMapper) {
        super(authenticator);
        setProviderId(providerId);
        setName(displayName);
        setUserDetailsContextMapper(contextMapper);
    }

    @SuppressWarnings("unused")
    public XnatLdapAuthenticationProvider(final LdapAuthenticator authenticator, final LdapAuthoritiesPopulator authoritiesPopulator) {
        super(authenticator, authoritiesPopulator);
    }

    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        final Authentication processed = super.authenticate(authentication);
        log.debug("Found auth object of type: {} (principal is: {})", processed.getClass(), processed.getPrincipal().getClass());

        /*
         * Unlike the other authentication providers, we hafta do this check here. This class is on a different branch
         * of the class hierarchy, and so doesn't inherit additionalAuthenticationChecks.
         */
        final UserDetails userDetails = (UserDetails) processed.getPrincipal();
        if (!UserI.class.isAssignableFrom(userDetails.getClass())) {
            throw new AuthenticationServiceException("User details class is not of a type I know how to handle: " + userDetails.getClass());
        }
        final UserI xdatUserDetails = (UserI) userDetails;
        if (!xdatUserDetails.isEnabled()) {
            throw new DisabledException("Attempted login to disabled account: " + xdatUserDetails.getUsername());
        }
        if ((XDAT.getSiteConfigPreferences().getEmailVerification() && !xdatUserDetails.isVerified()) || !xdatUserDetails.isAccountNonLocked()) {
            throw new CredentialsExpiredException("Attempted login to unverified or locked account: " + xdatUserDetails.getUsername());
        }

        return processed;
    }

    @Override
    public String getName() {
        return _displayName;
    }

    public void setName(final String newName) {
        _displayName = newName;
    }

    @Override
    public String getProviderId() {
        return _providerId;
    }

    public void setProviderId(final String providerId) {
        _providerId = providerId;
    }

    @Override
    public String getAuthMethod() {
        return XdatUserAuthService.LDAP;
    }

    @Override
    public int getOrder() {
        return _order;
    }

    @Override
    public void setOrder(final int order) {
        _order = order;
    }

    @Override
    public XnatAuthenticationToken createToken(final String username, final String password) {
        return new XnatLdapUsernamePasswordAuthenticationToken(username, password, getProviderId());
    }

    /**
     * Indicates whether this provider supports the specified authentication token. The LDAP authentication provider
     * supports tokens that implement or extend the {@link XnatLdapUsernamePasswordAuthenticationToken} class. Note
     * that even that may not be sufficient: {@link XnatAuthenticationProvider} implementations also check the
     * {@link XnatAuthenticationToken#getProviderId() token's provider ID} to ensure that it matches the {@link
     * XnatAuthenticationProvider#getProviderId() provider implementation and configurations' ID}. That check is
     * supported by the {@link #supports(Authentication)} method.
     *
     * @param authentication The authentication token type to test.
     *
     * @return Returns <b>true</b> if this provider supports the submitted token type.
     */
    @Override
    public boolean supports(final Class<?> authentication) {
        return XnatLdapUsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Indicates whether this provider supports the specified authentication token. The LDAP authentication provider
     * supports tokens that implement or extend the {@link XnatLdapUsernamePasswordAuthenticationToken} class but this
     * method may also {@link XnatAuthenticationToken#getProviderId() token's provider ID} to ensure that it matches
     * the {@link XnatAuthenticationProvider#getProviderId() provider implementation and configurations' ID}.
     *
     * @param authentication The authentication token to test.
     *
     * @return Returns <b>true</b> if this provider supports the submitted token.
     */
    @Override
    public boolean supports(final Authentication authentication) {
        return supports(authentication.getClass()) &&
               authentication instanceof XnatLdapUsernamePasswordAuthenticationToken &&
               StringUtils.equals(getProviderId(), ((XnatLdapUsernamePasswordAuthenticationToken) authentication).getProviderId());
    }

    /**
     * Indicates whether the provider should be visible to and selectable by users. <b>false</b> usually indicates an
     * internal authentication provider, e.g. token authentication. The LDAP authentication provider is visible by
     * default.
     *
     * @return <b>true</b> if the provider should be visible to and usable by users.
     */
    @Override
    public boolean isVisible() {
        return _visible;
    }

    /**
     * Sets whether the provider should be visible or not as an option for user.
     *
     * @param visible Whether the provider should be visible to and usable by users.
     */
    @Override
    public void setVisible(final boolean visible) {
        _visible = visible;
    }

    @Override
    public String toString() {
        return getName();
    }

    private String  _displayName = "";
    private String  _providerId  = "";
    private int     _order       = -1;
    private boolean _visible     = true;
}
