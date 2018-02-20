package org.nrg.xnat.auth.ldap;

import lombok.extern.slf4j.Slf4j;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.provider.XnatMulticonfigLdapAuthenticationProvider;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.springframework.context.annotation.Bean;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;

@XnatPlugin(value = "xnat-ldap-auth-plugin", name = "XNAT LDAP Authentication Provider Plugin")
@Slf4j
public class XnatLdapAuthPlugin {
    @Bean
    public LdapAuthenticationProvider multiconfigLdapAuthenticationProvider(final XdatUserAuthService userAuthService, final SiteConfigPreferences preferences, final AuthenticationProviderConfigurationLocator locator) {
        return new XnatMulticonfigLdapAuthenticationProvider(locator, userAuthService, preferences);
    }
}
