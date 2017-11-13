package org.nrg.xnat.auth.ldap.config;

import org.nrg.framework.beans.AbstractConfigurableBeanConfiguration;
import org.nrg.xnat.auth.ldap.XnatLdapUserDetailsMapper;
import org.nrg.xnat.auth.ldap.provider.XnatLdapAuthenticationProvider;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;

import java.util.Map;

@Configuration
public class LdapProviderConfiguration extends AbstractConfigurableBeanConfiguration<XnatLdapAuthenticationProvider> {
    public LdapProviderConfiguration() {
        super(AuthenticationProvider.class);
    }

    @Override
    public void setBeanInitializationParameters() {
        addBeanInitializationParameters("ldap1", );
        final XnatLdapAuthenticationProvider provider = new XnatLdapAuthenticationProvider(getBindAuthenticator(properties, getLdapContextSource(properties)));
        provider.setUserDetailsContextMapper(new XnatLdapUserDetailsMapper(id, properties, _userAuthService));
        provider.setName(name);
        provider.setProviderId(id);
        if (properties.get("order") != null) {
            provider.setOrder(Integer.parseInt(properties.get("order")));
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

}
