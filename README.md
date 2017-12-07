# XNAT LDAP Authentication Provider Plugin #

This is the XNAT 1.7 Authentication Provider Plugin. It replaces previous support for LDAP inside of XNAT itself.

## Building ##

**Note:** Once this plugin is released, the preferred way to get the plugin is by downloading it from the [XNAT Marketplace](https://marketplace.xnat.org).

To build the XNAT LDAP authentication provider plugin:

1. If you haven't already, clone [this repository](https://bitbucket.org/xnatx/xnat-ldap-auth-plugin.git) and cd to the newly cloned folder.

1. Build the plugin:

    `./gradlew clean jar distZip` 
    
    On Windows, you can use the batch file:
    
    `gradlew.bat clean jar distZip`
    
    This should build the plugin in the file **build/libs/xnat-ldap-auth-plugin-1.0.0-SNAPSHOT.jar** 
    (the version may differ based on updates to the code).
    
1. Copy the plugin jar to your plugins folder: 

    `cp build/libs/xnat-xnat-ldap-auth-plugin-1.0.0-SNAPSHOT.jar /data/xnat/home/plugins`

## Configuring and Testing ##

XNAT searches for authenticatin server configurations by looking for files whose names match the pattern:

    *-provider.properties
    
It looks in the following locations:

* On the classpath in the folder **META-INF/xnat/auth**
* In a folder named **auth** under the XNAT home folder (usually configured with the **xnat.home** system variable)

This plugin will use any entries located in any of those properties files where the property **type** is set to [XdatUserAuthService.LDAP](https://bitbucket.org/xnatdev/xdat/src/master/src/main/java/org/nrg/xdat/services/XdatUserAuthService.java#XdatUserAuthService.java-21)
(which is just "ldap") to configure one or more LDAP repositories.

You can use the file [ldap-provider-sample.properties](src/main/resources/ldap-provider-sample.properties) as a starting point. The values
specified in that file have been tested and verified against the LDAP configuration in the default [XNAT LDAP Server Vagrant project](https://bitbucket.org/xnatdev/xnat-ldap-vagrant).

You can test provider properties against an LDAP server using the [ValidateLdap.groovy](src/main/resources) script (running this script requires
having [Groovy][https://groovy-lang.org] installed and the plugin jar available). To run the test script, use following syntax:

`groovy 'jar:file:path/to/ldap-auth-plugin-1.0.0-SNAPSHOT.jar!/ValidateLdap.groovy' [properties-file]`

On Linux or OS X, the "'" characters are required to prevent the "!" character from being detected by the shell interpreter. You can prefix the "!"
with a backslash ("\\") instead.

If you don't specify a properties file, the validate script will use the same default values as specified in **ldap-provider-sample.properties**, along with 
the default user **asmith** and password **password**. You can specify a properties file that only overrides a few properties in the sample configuration as 
well, otherwise inheriting the values for the default properties. The username and password properties aren't normally configured in the provider properties
definition but can be specified for the LDAP validator with the properties **user** and **pass** (note that password is already used in the provider 
definition, but indicates the password for the LDAP binding account and stays the same regardless of the specific username and password being validated). 

The output from a successful validation looks something like this:

    $ groovy 'jar:file:build/libs/ldap-auth-plugin-1.0.0-SNAPSHOT.jar!/ValidateLdap.groovy'
    Dec 06, 2017 3:18:45 PM org.springframework.security.ldap.DefaultSpringSecurityContextSource <init>
    INFO:  URL 'ldap://ldap.xnat.org', root DN is ''
    User asmith authentication state: true

## Deploying ##

Deploying your XNAT plugin requires the following steps:

1. Copy the plugin jar to the **plugins** folder for your XNAT installation. The location of the 
**plugins** folder varies based on how and where you have installed your XNAT. If you are running 
a virtual machine created through the [XNAT Vagrant project](https://bitbucket/xnatdev/xnat-vagrant.git),
you can copy the plugin to the appropriate configuration folder and then copy it within the VM from 
**/vagrant** to **/data/xnat/home/plugins**.

1. Restart the Tomcat server. Your new plugin will be available as soon as the restart and initialization process is completed.


