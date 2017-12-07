package org.nrg.xnat.auth.ldap;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.framework.beans.AbstractConfigurableBeanConfiguration;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.provider.XnatLdapAuthenticationProvider;
import org.nrg.xnat.security.BaseXnatSecurityExtension;
import org.nrg.xnat.security.XnatSecurityExtension;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import java.util.Collections;
import java.util.Map;
import java.util.Properties;

@XnatPlugin(value = "xnat-ldap-auth-plugin", name = "XNAT LDAP Authentication Provider Plugin")
@Slf4j
public class LdapAuthPlugin { // extends AbstractConfigurableBeanConfiguration<XnatLdapAuthenticationProvider> {
    /*
    public LdapAuthPlugin() {
        super(AuthenticationProvider.class);
    }
    */

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

    /*
    @Override
    public void setBeanInitializationParameters(final BeanDefinitionRegistry registry) {
        for (final String providerId : _ldapProviderDefinitions.keySet()) {
            final Properties                properties = _ldapProviderDefinitions.get(providerId);
            final XnatLdapUserDetailsMapper mapper     = new XnatLdapUserDetailsMapper(providerId, _userAuthService, _preferences, properties);

            if (StringUtils.isNotBlank(properties.getProperty("order"))) {
                final int order = Integer.parseInt(properties.getProperty("order"));
                addBeanInitializationParameters(providerId, properties.getProperty("name"), mapper, getBindAuthenticator(properties, getLdapContextSource(properties)), order);
            } else {
                addBeanInitializationParameters(providerId, properties.getProperty("name"), mapper, getBindAuthenticator(properties, getLdapContextSource(properties)));
            }
        }
    }
    */

    @Bean
    public XnatSecurityExtension ldapSecurityExtension() {
        return new BaseXnatSecurityExtension() {
            @Override
            public String getAuthMethod() {
                return XdatUserAuthService.LDAP;
            }

            @Override
            public void configure(final HttpSecurity http) throws Exception {
                http.authorizeRequests()
                    .anyRequest().permitAll()
                    .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                        public <O extends FilterSecurityInterceptor> O postProcess(final O interceptor) {
                            interceptor.setPublishAuthorizationSuccess(true);
                            return interceptor;
                        }
                    });

            }

            @Override
            public void configure(final AuthenticationManagerBuilder builder) throws Exception {
                builder.ldapAuthentication().withObjectPostProcessor(new ObjectPostProcessor<LdapAuthenticationProvider>() {
                    @Override
                    public <O extends LdapAuthenticationProvider> O postProcess(final O provider) {
                        return provider;
                    }
                });
//                type=ldap
//                address=ldap://ldap.xnat.org/dc=xnat,dc=org
//                userdn=cn=admin,dc=xnat,dc=org
//                password=admin
//                search.base=ou=Users,dc=xnat,dc=org
//                search.filter=(uid={0})

            }
        };
    }

    private XdatUserAuthService     _userAuthService;
    private SiteConfigPreferences   _preferences;
    private Map<String, Properties> _ldapProviderDefinitions;
}
