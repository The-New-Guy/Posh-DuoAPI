<#

    This file should contain the Duo environment info. For details on the proper format of the hashtables below please see the README file.

#>

# If the -DuoEnv parameter is not used during an API call then the DuoDefaultEnv value below will be used to determine which Duo environment configuration to use.
$script:DuoDefaultEnv = 'Prod'

$script:DuoEnvironmentInfo = @{

    Prod = @{

        # Required Keys.

        IntegrationKey = 'DIxxxxxxxxxxxxxxxxxx'
        SecretKey = 'YourSecretsHere'
        ApiHostname = 'api-nnnnnxnx.duosecurity.com'

        # Optional keys.

        # ProxyServer = 'your-proxy-01.domain.local'
        # ProxyPort = 8080
        # ProxyBypassList = @('*.domain.local', '*.otherdomain.local')
        # ProxyBypassOnLocal = $true
        # ProxyUsername = 'janedoe'
        # ProxyPassword = 'YourProxySecretsHere'

    }

    Test = @{

        # Required Keys.

        IntegrationKey = 'DIxxxxxxxxxxxxxxxxxx'
        SecretKeyEncrypted = 'Big long protected SecureString represented as a string on 1 line here'
        ApiHostname = 'api-nnnnnxnx.duosecurity.com'

        # Optional keys.

        # ProxyServer = 'your-proxy-01.domain.local'
        # ProxyPort = 8080
        # ProxyBypassList = @('*.domain.local', '*.otherdomain.local')
        # ProxyBypassOnLocal = $true
        # ProxyUsername = 'janedoe'
        # ProxyPasswordEncrypted = 'Big long protected SecureString represented as a string on 1 line here'

    }

    Dev = @{

        # Required Keys.

        IntegrationKey = 'DIxxxxxxxxxxxxxxxxxx'
        SecretKeyEncrypted = 'Big long protected SecureString represented as a string on 1 line here'
        ApiHostname = 'api-nnnnnxnx.duosecurity.com'

        # Optional keys.

        # ProxyServer = 'your-proxy-01.domain.local'
        # ProxyPort = 8080
        # ProxyBypassList = @('*.domain.local', '*.otherdomain.local')
        # ProxyBypassOnLocal = $true
        # ProxyUseDefaultCredentials = $true

    }
}