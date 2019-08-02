@Grapes([@Grab("org.springframework.security:spring-security-ldap:4.2.3.RELEASE"), @Grab("org.apache.commons:commons-lang3:3.7"), @Grab("org.slf4j:slf4j-nop:1.7.25")])

import org.apache.commons.lang3.StringUtils
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.ldap.DefaultSpringSecurityContextSource
import org.springframework.security.ldap.authentication.BindAuthenticator
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch

final String propertiesFile = this.args.length == 0 ? "ldap.properties" : StringUtils.appendIfMissing(this.args[0], ".properties")

final Properties properties = new Properties()
def file = new File(propertiesFile)
if (file.exists()) {
    println "Loading properties from ${file.path}"
    file.withInputStream {
        properties.load it
    }
} else {
    println "No properties file found, using default values"
}

def address = properties.getProperty "address", "ldap://ldap.xnat.org"
def userDn = properties.getProperty "userdn", "cn=admin,dc=xnat,dc=org"
def bindingPassword = properties.getProperty "password", "password"
def searchBase = properties.getProperty "search.base", "ou=users,dc=xnat,dc=org"
def searchFilter = properties.getProperty "search.filter", "(uid={0})"
def username = properties.getProperty "validate.username", "asmith"
def password = properties.getProperty "validate.password", "password"

println ""
println "Address:       ${address}"
println "User DN:        ${userDn}"
println "Password:      ${bindingPassword}"
println "Search base:   ${searchBase}"
println "Search filter: ${searchFilter}"
println "Username:      ${username}"
println "password:      ${password}"
println ""

def contextSource = new DefaultSpringSecurityContextSource(address)
contextSource.setUserDn userDn
contextSource.setPassword bindingPassword
contextSource.afterPropertiesSet()

final String[] atoms = userDn.split ",", 2
def bindingUsername = atoms[0]
def bindingSearchBase = atoms.size() > 1 ? (atoms[1]) : ""

println "Binding account '${bindingUsername}', user account '${username}"
BindAndAuthenticate(contextSource, searchBase, searchFilter, username, password)


private boolean BindAndAuthenticate(DefaultSpringSecurityContextSource contextSource, String searchBase, String searchFilter, username, String password) {
    println "Creating user search object with search base '${searchBase}' and filter '${searchFilter}"
    def ldapBindAuthenticator = new BindAuthenticator(contextSource)
    ldapBindAuthenticator.setUserSearch new FilterBasedLdapUserSearch(searchBase, searchFilter, contextSource)

    def provider = new LdapAuthenticationProvider(ldapBindAuthenticator)

    try {
        final Authentication authentication = provider.authenticate new UsernamePasswordAuthenticationToken(username, password)
        println "User '${authentication.principal.username}' authentication state: ${authentication.authenticated}"
        authentication.authenticated
    } catch (BadCredentialsException ignored) {
        println "Bad credentials for user '${username}'"
        false
    } catch (UsernameNotFoundException ignored) {
        println "Couldn't find user '${username}'"
        false
    } catch (AuthenticationException exception) {
        println "Some kind of authentication exception occurred for user '${username}':"
        println "${exception.class.name}: ${exception.message}"
        false
    }
}

