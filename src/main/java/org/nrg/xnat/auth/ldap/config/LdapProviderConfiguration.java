package org.nrg.xnat.auth.ldap.config;

import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.beans.AbstractConfigurableBeanConfiguration;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.XnatLdapUserDetailsMapper;
import org.nrg.xnat.auth.ldap.provider.XnatLdapAuthenticationProvider;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;

import java.util.Map;
import java.util.Properties;

// TODO: It's probably not necessary to have this separated from the LdapAuthPlugin configuration.
@Configuration
public class LdapProviderConfiguration extends AbstractConfigurableBeanConfiguration<XnatLdapAuthenticationProvider> {
    @Autowired
    public LdapProviderConfiguration(final SiteConfigPreferences preferences, final XdatUserAuthService userAuthService, final AuthenticationProviderConfigurationLocator locator) {
        super(AuthenticationProvider.class);
        _preferences = preferences;
        _userAuthService = userAuthService;
        _ldapProviderDefinitions = locator.getProviderDefinitions("ldap");
    }

    @Override
    public void setBeanInitializationParameters() {
        for (final String providerId : _ldapProviderDefinitions.keySet()) {
            final Properties properties = _ldapProviderDefinitions.get(providerId);
            if (StringUtils.isNotBlank(properties.getProperty("order"))) {
                final int order = Integer.parseInt(properties.getProperty("order"));
                addBeanInitializationParameters(providerId, properties.getProperty("name"), getBindAuthenticator(properties, getLdapContextSource(properties)), new XnatLdapUserDetailsMapper(providerId, properties, _userAuthService, _preferences), order);
            } else {
                addBeanInitializationParameters(providerId, properties.getProperty("name"), getBindAuthenticator(properties, getLdapContextSource(properties)), new XnatLdapUserDetailsMapper(providerId, properties, _userAuthService, _preferences));
            }
        }
    }

    private BindAuthenticator getBindAuthenticator(final Properties properties, final DefaultSpringSecurityContextSource ldapServer) {
        final BindAuthenticator ldapBindAuthenticator = new BindAuthenticator(ldapServer);
        ldapBindAuthenticator.setUserSearch(new FilterBasedLdapUserSearch(properties.getProperty("search.base"), properties.getProperty("search.filter"), ldapServer));
        return ldapBindAuthenticator;
    }

    private DefaultSpringSecurityContextSource getLdapContextSource(final Properties properties) {
        return new DefaultSpringSecurityContextSource(properties.getProperty("address")) {{
            setUserDn(properties.getProperty("userdn"));
            setPassword(properties.getProperty("password"));
            afterPropertiesSet();
        }};
    }

    private final SiteConfigPreferences   _preferences;
    private final XdatUserAuthService     _userAuthService;
    private final Map<String, Properties> _ldapProviderDefinitions;
}
