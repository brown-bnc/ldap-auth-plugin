package org.nrg.xnat.auth.ldap;

import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.config.LdapAuthenticationProviderConfigurator;
import org.springframework.context.annotation.Bean;

@XnatPlugin(value = "xnat-ldap-auth-plugin", name = "XNAT LDAP Authentication Provider Plugin")
public class LdapAuthPlugin {
    @Bean
    public LdapAuthenticationProviderConfigurator ldapConfigurator(final XdatUserAuthService service, final SiteConfigPreferences preferences) {
        return new LdapAuthenticationProviderConfigurator(service, preferences);
    }
}
