/*
 * web: XnatLdapUserDetailsMapper
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnat.auth.ldap;

import lombok.extern.slf4j.Slf4j;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

@Component
@Slf4j
public class XnatLdapUserDetailsMapper extends LdapUserDetailsMapper implements LdapAuthoritiesPopulator {
    public XnatLdapUserDetailsMapper(final String providerId, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences, final Properties properties) {
        super();
        Assert.hasText(providerId, "You must provide an authentication provider ID.");
        Assert.notEmpty(properties, "You must provide the authentication provider properties.");
        log.info("Creating user details mapper with the provider ID [{}] and {}", providerId, (properties != null && properties.size() > 0 ? "mapping properties: " + properties.toString() : "default mapping properties"));

        _providerId = providerId;
        _userAuthService = userAuthService;
        _preferences = preferences;

        if (properties == null || properties.size() == 0) {
            _properties = new Properties() {{
                setProperty(PROPERTY_EMAIL, "mail");
                setProperty(PROPERTY_FIRST, "givenName");
                setProperty(PROPERTY_LAST, "sn");
            }};
        } else {
            if (!properties.containsKey(PROPERTY_EMAIL)) {
                properties.setProperty(PROPERTY_EMAIL, "mail");
            }
            if (!properties.containsKey(PROPERTY_FIRST)) {
                properties.setProperty(PROPERTY_FIRST, "givenName");
            }
            if (!properties.containsKey(PROPERTY_LAST)) {
                properties.setProperty(PROPERTY_LAST, "sn");
            }
            _properties = properties;
        }
    }

    @Override
    public UserI mapUserFromContext(final DirContextOperations context, final String username, final Collection<? extends GrantedAuthority> authorities) {
        final String email     = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_EMAIL));
        final String firstName = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_FIRST));
        final String lastName  = (String) context.getObjectAttribute(_properties.getProperty(PROPERTY_LAST));

        UserI userDetails = _userAuthService.getUserDetailsByNameAndAuth(username, XdatUserAuthService.LDAP, _providerId, email, lastName, firstName);

        try {
            final UserI xdatUser = Users.getUser(userDetails.getUsername());
            if ((!_preferences.getEmailVerification() || xdatUser.isVerified()) && userDetails.getAuthorization().isEnabled()) {
                return userDetails;
            } else {
                throw new NewAutoAccountNotAutoEnabledException(
                        "Successful first-time authentication via LDAP, but accounts are not auto-enabled or email verification required.  We'll treat this the same as we would a user registration"
                        , userDetails
                );
            }
        } catch (Exception e) {
            throw new NewAutoAccountNotAutoEnabledException(
                    "Successful first-time authentication via LDAP, but accounts are not auto-enabled or email verification required.  We'll treat this the same as we would a user registration"
                    , userDetails
            );
        }
    }

    @Override
    public void mapUserToContext(final UserDetails user, final DirContextAdapter contextAdapter) {
        throw new UnsupportedOperationException("LdapUserDetailsMapper only supports reading from a context.");
    }

    @Override
    public Collection<GrantedAuthority> getGrantedAuthorities(final DirContextOperations userData, final String username) {
        return ROLE_USER;
    }

    private static final List<GrantedAuthority> ROLE_USER       = Collections.singletonList((GrantedAuthority) new SimpleGrantedAuthority("ROLE_USER"));
    private static final String                 PROPERTY_PREFIX = "attributes.";
    private static final String                 PROPERTY_EMAIL  = PROPERTY_PREFIX + "email";
    private static final String                 PROPERTY_FIRST  = PROPERTY_PREFIX + "firstname";
    private static final String                 PROPERTY_LAST   = PROPERTY_PREFIX + "lastname";

    private final String                _providerId;
    private final XdatUserAuthService   _userAuthService;
    private final SiteConfigPreferences _preferences;
    private final Properties            _properties;
}
