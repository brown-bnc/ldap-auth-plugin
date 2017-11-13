/*
 * web: LdapAuthenticationProviderConfigurator
 * XNAT http://www.xnat.org
 * Copyright (c) 2005-2017, Washington University School of Medicine and Howard Hughes Medical Institute
 * All Rights Reserved
 *
 * Released under the Simplified BSD.
 */

package org.nrg.xnat.auth.ldap.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.NotImplementedException;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.XnatLdapUserDetailsMapper;
import org.nrg.xnat.auth.ldap.provider.XnatLdapAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Slf4j
public class LdapAuthenticationProviderConfigurator { // extends AbstractAuthenticationProviderConfigurator {
    @Autowired
    public LdapAuthenticationProviderConfigurator(final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        super();
        // setConfiguratorId("ldap");
        _userAuthService = userAuthService;
        _preferences = preferences;
    }

    // @Override
    public List<AuthenticationProvider> getAuthenticationProviders(String id, String name) {
        throw new NotImplementedException("You must provide LDAP properties in order to configure an LDAP connection.");
    }

    // @Override
    public List<AuthenticationProvider> getAuthenticationProviders(String id, String name, Map<String, String> properties) {
        try {
            final XnatLdapAuthenticationProvider provider = new XnatLdapAuthenticationProvider(getBindAuthenticator(properties, getLdapContextSource(properties)));
            provider.setUserDetailsContextMapper(new XnatLdapUserDetailsMapper(id, properties, _userAuthService));
            provider.setName(name);
            provider.setProviderId(id);
            if (properties.get("order") != null) {
                provider.setOrder(Integer.parseInt(properties.get("order")));
            }
            return Arrays.asList(new AuthenticationProvider[] { provider });
        } catch (Exception exception) {
            log.error("Something went wrong when configuring the LDAP authentication provider", exception);
            return null;
        }
    }

    private BindAuthenticator getBindAuthenticator(final Map<String, String> properties, final DefaultSpringSecurityContextSource ldapServer) {
        BindAuthenticator ldapBindAuthenticator = new BindAuthenticator(ldapServer);
        ldapBindAuthenticator.setUserSearch(new FilterBasedLdapUserSearch(properties.get("search.base"), properties.get("search.filter"), ldapServer));
        return ldapBindAuthenticator;
    }

    private DefaultSpringSecurityContextSource getLdapContextSource(final Map<String, String> properties) {
        return new DefaultSpringSecurityContextSource(properties.get("address")) {{
            setUserDn(properties.get("userdn"));
            setPassword(properties.get("password"));
            afterPropertiesSet();
        }};
    }

    private final XdatUserAuthService _userAuthService;
    private final SiteConfigPreferences _preferences;
}
