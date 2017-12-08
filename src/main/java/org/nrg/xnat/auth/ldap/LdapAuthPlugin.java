package org.nrg.xnat.auth.ldap;

import lombok.extern.slf4j.Slf4j;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.provider.XnatMulticonfigLdapAuthenticationProvider;
import org.nrg.xnat.security.conditions.LdapAuthProvidersDefinedCondition;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;

import java.util.Collections;
import java.util.Map;
import java.util.Properties;

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
    public void setAuthenticationProviderConfigurationLocator(final AuthenticationProviderConfigurationLocator locator) {
        final Map<String, Properties> definitions = locator.getProviderDefinitions("ldap");
        _ldapProviderDefinitions = definitions != null ? definitions : Collections.<String, Properties>emptyMap();
    }

    @Bean
    @Conditional(LdapAuthProvidersDefinedCondition.class)
    public LdapAuthenticationProvider multiconfigLdapAuthenticationProvider() {
        return new XnatMulticonfigLdapAuthenticationProvider(_ldapProviderDefinitions, _userAuthService, _preferences);
    }

    private XdatUserAuthService     _userAuthService;
    private SiteConfigPreferences   _preferences;
    private Map<String, Properties> _ldapProviderDefinitions;
}
