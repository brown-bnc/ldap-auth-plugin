package org.nrg.xnat.auth.ldap;

import lombok.extern.slf4j.Slf4j;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.framework.configuration.ConfigPaths;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.provider.XnatMulticonfigLdapAuthenticationProvider;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;

@XnatPlugin(value = "xnat-ldap-auth-plugin", name = "XNAT LDAP Authentication Provider Plugin")
@Slf4j
public class LdapAuthPlugin {
    @Autowired
    public void setXdatUserAuthService(final XdatUserAuthService userAuthService) {
        _userAuthService = userAuthService;
    }

    @Autowired
    public void setSiteConfigPreferences(final SiteConfigPreferences preferences) {
        _preferences = preferences;
    }

    @Autowired
    public void setConfigPaths(final ConfigPaths configPaths) {
        _configPaths = configPaths;
    }

    @Autowired
    public void setMessageSource(final MessageSource messageSource) {
        _messageSource = messageSource;
    }

    @Bean
    public AuthenticationProviderConfigurationLocator ldapProviderConfigurationLocator() {
        return new AuthenticationProviderConfigurationLocator(XdatUserAuthService.LDAP, _configPaths, _messageSource);
    }

    @Bean
    // @Conditional(LdapAuthProvidersDefinedCondition.class)
    public LdapAuthenticationProvider multiconfigLdapAuthenticationProvider() {
        return new XnatMulticonfigLdapAuthenticationProvider(ldapProviderConfigurationLocator(), _userAuthService, _preferences);
    }

    private ConfigPaths           _configPaths;
    private MessageSource         _messageSource;
    private XdatUserAuthService   _userAuthService;
    private SiteConfigPreferences _preferences;
}
