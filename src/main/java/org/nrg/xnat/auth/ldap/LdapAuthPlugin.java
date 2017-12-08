package org.nrg.xnat.auth.ldap;

import com.google.common.base.Joiner;
import lombok.extern.slf4j.Slf4j;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.nrg.xdat.services.XdatUserAuthService;
import org.nrg.xnat.auth.ldap.provider.XnatMulticonfigLdapAuthenticationProvider;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.ConfigurationCondition;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.util.ObjectUtils;

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
    @Conditional(LdapAuthProvidersDefined.class)
    public LdapAuthenticationProvider multiconfigLdapAuthenticationProvider() {
        return new XnatMulticonfigLdapAuthenticationProvider(_ldapProviderDefinitions, _userAuthService, _preferences);
    }

    class LdapAuthProvidersDefined implements ConfigurationCondition {
        @Override
        public ConfigurationPhase getConfigurationPhase() {
            return ConfigurationPhase.REGISTER_BEAN;
        }

        @Override
        public boolean matches(final ConditionContext context, final AnnotatedTypeMetadata metadata) {
            final ListableBeanFactory factory = context.getBeanFactory();
            final AuthenticationProviderConfigurationLocator locator = BeanFactoryUtils.beanOfType(factory, AuthenticationProviderConfigurationLocator.class);
            if (ObjectUtils.isEmpty(locator)) {
                log.debug("Didn't find an auth provider configuration locator, nothing to do");
                return false;
            }
            final Map<String, Properties> definitions = locator.getProviderDefinitions(XdatUserAuthService.LDAP);
            if (ObjectUtils.isEmpty(locator)) {
                log.debug("Found an auth provider configuration locator, but it doesn't have any LDAP providers, nothing to do");
                return false;
            }
            log.debug("Found locator bean with {} LDAP providers defined: {}", definitions.size(), Joiner.on(", ").join(definitions.keySet()));
            return true;
        }
    }

    private XdatUserAuthService     _userAuthService;
    private SiteConfigPreferences   _preferences;
    private Map<String, Properties> _ldapProviderDefinitions;
}
