package org.nrg.xnat.auth.ldap.provider;

import lombok.extern.slf4j.Slf4j;
import org.nrg.xnat.security.provider.XnatAuthenticationProviderValidator;
import org.slf4j.helpers.MessageFormatter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.stereotype.Component;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Properties;

import static org.nrg.xnat.auth.ldap.provider.XnatLdapAuthenticationProvider.*;

@Component
@Slf4j
public class XnatLdapAuthenticationProviderValidator implements XnatAuthenticationProviderValidator<XnatLdapAuthenticationProvider> {
    public String validate(final XnatLdapAuthenticationProvider provider) {
        return validate(provider.getAttributes().getProperties());
    }

    public String validate(final Properties properties) {
        final String address         = properties.getProperty(LDAP_ADDRESS, "ldap://ldap.xnat.org");
        final String userDn          = properties.getProperty(LDAP_USERDN, "cn=admin,dc=xnat,dc=org");
        final String bindingPassword = properties.getProperty(LDAP_PASSWORD, "password");
        final String searchBase      = properties.getProperty(LDAP_SEARCH_BASE, "ou=users,dc=xnat,dc=org");
        final String searchFilter    = properties.getProperty(LDAP_SEARCH_FILTER, "(uid={0})");
        final String username        = properties.getProperty(LDAP_VALIDATE_USERNAME, "asmith");
        final String password        = properties.getProperty(LDAP_VALIDATE_PASSWORD, "password");

        println("Address:       {}", address);
        println("User DN:       {}", userDn);
        println("Search base:   {}", searchBase);
        println("Search filter: {}", searchFilter);
        println("Username:      {}", username);

        final DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(address);
        contextSource.setUserDn(userDn);
        contextSource.setPassword(bindingPassword);
        contextSource.afterPropertiesSet();

        final String[] atoms = userDn.split(",", 2);

        final String  bindingSearchBase        = atoms.length > 1 ? atoms[1] : "";
        final String  bindingUsername          = atoms[0];

        println("Validating the binding user account '{}' with search base '{}'", bindingUsername, bindingSearchBase);
        final boolean bindingUserAuthenticated = bindAndAuthenticate(contextSource, bindingSearchBase, "(${bindingUsername})", bindingUsername, bindingPassword);

        if (bindingUserAuthenticated) {
            println("Binding user '{}' authenticated successfully, validating the user account '{}'", bindingUsername, username);
            bindAndAuthenticate(contextSource, searchBase, searchFilter, username, password);
        }

        final String message = _buffer.getBuffer().toString();
        log.info(message);
        return message;
    }

    private boolean bindAndAuthenticate(final DefaultSpringSecurityContextSource contextSource, final String searchBase, final String searchFilter, final String username, final String password) {
        final BindAuthenticator ldapBindAuthenticator = new BindAuthenticator(contextSource);
        ldapBindAuthenticator.setUserSearch(new FilterBasedLdapUserSearch(searchBase, searchFilter, contextSource));

        final LdapAuthenticationProvider provider = new LdapAuthenticationProvider(ldapBindAuthenticator);

        try {
            final Authentication authentication = provider.authenticate(new UsernamePasswordAuthenticationToken(username, password));
            final UserDetails    principal      = (UserDetails) authentication.getPrincipal();
            println("User {} authentication state: {}", principal.getUsername(), authentication.isAuthenticated());
            return authentication.isAuthenticated();
        } catch (BadCredentialsException ignored) {
            println("Bad credentials for user {}", username);
        } catch (UsernameNotFoundException ignored) {
            println("Couldn't find user {}", username);
        } catch (AuthenticationException exception) {
            println("Some kind of authentication exception occurred for user {}:", username);
            println("{}: {}", exception.getClass().getName(), exception.getMessage());
        }
        return false;
    }

    private void println(final String text, final Object... variables) {
        _writer.println(MessageFormatter.arrayFormat(text, variables));
    }

    private final StringWriter _buffer = new StringWriter();
    private final PrintWriter  _writer = new PrintWriter(_buffer);
}
