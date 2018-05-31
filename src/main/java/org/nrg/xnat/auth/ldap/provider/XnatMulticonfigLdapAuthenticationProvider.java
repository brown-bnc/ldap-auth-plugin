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
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.XnatLdapUserDetailsMapper;
import org.nrg.xnat.auth.ldap.tokens.XnatLdapUsernamePasswordAuthenticationToken;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.nrg.xnat.security.provider.ProviderAttributes;
import org.nrg.xnat.security.provider.XnatAuthenticationProvider;
import org.nrg.xnat.security.provider.XnatMulticonfigAuthenticationProvider;
import org.nrg.xnat.security.tokens.XnatAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.stereotype.Component;

import java.util.*;

import static org.nrg.xdat.services.XdatUserAuthService.LDAP;

/**
 * This class represents both an individual LDAP provider and, in the case where multiple LDAP configurations are provided
 * for a single deployment, an aggregator of LDAP providers. This differs from earlier releases of XNAT where multiple LDAP
 * configurations were represented as multiple provider instances.
 */
@Component
@Slf4j
public class XnatMulticonfigLdapAuthenticationProvider extends XnatLdapAuthenticationProvider implements XnatMulticonfigAuthenticationProvider {
    @Autowired
    public XnatMulticonfigLdapAuthenticationProvider(final AuthenticationProviderConfigurationLocator locator, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        this(locator.getProviderDefinitionsByType(LDAP), userAuthService, preferences);
    }

    public XnatMulticonfigLdapAuthenticationProvider(final Map<String, ProviderAttributes> definitions, final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences) {
        super(getPrimaryAuthenticator(definitions));

        final List<ProviderAttributes> configurations = getOrderedConfigurations(definitions);

        // We've already initialized the super class with the primary bind authenticator, now we just need to
        // set the remaining provider properties for this instance. All of the other providers go into the map.
        final ProviderAttributes primary           = configurations.remove(0);
        final String             primaryProviderId = primary.getProviderId();

        setProviderId(primaryProviderId);
        setName(primary.getName());
        setVisible(primary.isVisible());
        setOrder(primary.getOrder());
        setUserDetailsContextMapper(new XnatLdapUserDetailsMapper(primaryProviderId, userAuthService, preferences, primary.getProperties()));

        _providerIds.add(primaryProviderId);
        _providerAttributes.put(primaryProviderId, primary);

        for (final ProviderAttributes configuration : configurations) {
            final String providerId = configuration.getProviderId();

            _providerIds.add(providerId);
            _providerAttributes.put(providerId, configuration);
            _providers.put(providerId, new XnatLdapAuthenticationProvider(providerId, configuration.getName(), getBindAuthenticator(configuration), new XnatLdapUserDetailsMapper(providerId, userAuthService, preferences, configuration.getProperties())));
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Authentication authenticate(final Authentication authentication) throws AuthenticationException {
        // Try the primary first. If we find it there and it's authenticated, then return that, our work here is done.
        final Authentication primary = super.authenticate(authentication);
        if (primary != null && primary.isAuthenticated()) {
            return primary;
        }

        // If we didn't find it in the primary provider, loop through the nested providers.
        for (final String providerId : _providers.keySet()) {
            final XnatLdapAuthenticationProvider provider  = _providers.get(providerId);
            final Authentication                 processed = provider.authenticate(authentication);
            if (processed != null && processed.isAuthenticated()) {
                return processed;
            }
        }

        // We didn't find anything so return null.
        return null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public List<String> getProviderIds() {
        return _providerIds;
    }

    @Override
    public List<XnatAuthenticationProvider> getProviders() {
        return new ArrayList<XnatAuthenticationProvider>(_providers.values());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public XnatAuthenticationProvider getProvider(final String providerId) {
        return StringUtils.equals(getProviderId(), providerId) ? this : _providers.get(providerId);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getName(final String providerId) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        return provider != null ? provider.getName() : null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isVisible(final String providerId) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        return provider != null && provider.isVisible();
    }

    @Override
    public void setVisible(final String providerId, final boolean visible) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        if (provider != null) {
            provider.setVisible(visible);
            _providerAttributes.get(providerId).setVisible(visible);
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public int getOrder(final String providerId) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        return provider != null ? provider.getOrder() : -1;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setOrder(final String providerId, final int order) {
        final XnatAuthenticationProvider provider = getProvider(providerId);
        if (provider != null) {
            provider.setOrder(order);
            _providerAttributes.get(providerId).setOrder(order);
        }
    }

    /**
     * {@inheritDoc}
     */
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

    @Override
    public String toString() {
        return getName();
    }

    private static LdapAuthenticator getPrimaryAuthenticator(final Map<String, ProviderAttributes> definitions) {
        return getBindAuthenticator(getOrderedConfigurations(definitions).get(0));
    }

    private static List<ProviderAttributes> getOrderedConfigurations(final Map<String, ProviderAttributes> definitions) {
        final List<ProviderAttributes> configurations = new ArrayList<>(definitions.values());
        Collections.sort(configurations);
        return configurations;
    }

    private static BindAuthenticator getBindAuthenticator(final ProviderAttributes provider) {
        final DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(provider.getProperty("address"));
        contextSource.setUserDn(provider.getProperty("userdn"));
        contextSource.setPassword(provider.getProperty("password"));
        contextSource.afterPropertiesSet();

        final BindAuthenticator ldapBindAuthenticator = new BindAuthenticator(contextSource);
        ldapBindAuthenticator.setUserSearch(new FilterBasedLdapUserSearch(provider.getProperty("search.base"), provider.getProperty("search.filter"), contextSource));
        return ldapBindAuthenticator;
    }

    private final List<String>                                _providerIds        = new ArrayList<>();
    private final Map<String, ProviderAttributes>             _providerAttributes = new HashMap<>();
    private final Map<String, XnatLdapAuthenticationProvider> _providers          = new HashMap<>();
}
