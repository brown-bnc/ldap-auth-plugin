package org.nrg.xnat.auth.ldap;

import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xnat.auth.ldap.config.LdapProviderConfiguration;
import org.springframework.context.annotation.Import;

@XnatPlugin(value = "xnat-ldap-auth-plugin", name = "XNAT LDAP Authentication Provider Plugin")
@Import(LdapProviderConfiguration.class)
public class LdapAuthPlugin {
}
