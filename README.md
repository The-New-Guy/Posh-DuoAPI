# Posh-DuoAPI

This is a PowerShell module that contains a set of wrappers for creating and sending Duo API calls. Documentation on Duo API can be found at the following locations:


- Duo Auth API - https://duo.com/docs/authapi
- Duo Admin API - https://duo.com/support/documentation/adminapi

For details on installing and using this module please refer to the following sections:

- [Installation](#Install)
- [Duo Environment Configuration](#DuoEnvConfig)
- [Examples](#Examples)

###### Note: This module has currently only be tested with the Duo Auth API and therefore only provides wrapper functions for the Duo Auth API. However, the Duo Admin API commands should be possible using the Invoke-DuoRequest command.

## <a name="Install"></a> Installation

1. Download the module (git clone or download the zip).

2. Place the module in your PSModulePath. Read more about PSModulePath [Here](https://msdn.microsoft.com/en-us/library/dd878324%28v=vs.85%29.aspx).

    ``` powershell
    Write-Host $env:PSModulePath
    ```

3. Get the Integration Key, Secret Key and API Hostname for your Duo API Integration. For details see [First Steps](https://duo.com/support/documentation/adminapi#first-steps).

4. Configure the Duo Environment Configuration using one of the methods detailed in the [Duo Environment Configuration](#DuoEnvConfig) section.

## <a name="DuoEnvConfig"></a> Duo Environment Configuration

In order to make Duo API calls this module will need the Duo API Integration keys provided to you for your application environment. These keys must be provided by your organization's Duo administrator. To configure this module for your Duo environment you will need to gather the following information:

- **Duo API Integration Key** - Application specific API integration key retrieved from your Duo Admin (ex. DIxxxxxxxxxxxxxxxxxx).
- **Duo API Secret Key** - Secret key associated with the integration key.
- **Duo API Hostname** - Environment specific API host that will handle the API calls (ex. api-nnnnnxnx.duosecurity.com).

To avoid typing in this information for every Duo API call, this module will use an internal hashtable to maintain this information for each application environment. The hashtable will support multiple application environments (integration keys) and will support the Duo Secret Key being stored as either a plain text string or an encrypted SecureString. This hashtable will have the following format where the keys to the main hashtable are the application environments:

``` powershell
DuoEnvironmentInfo = @{

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
```

1. The main hashtable must contain at least one properly formatted hashtable. If any of the nested hashtables are not in the proper format an error will be thrown.

2. The main hashtable must contain a key that matches the default Duo environment. The default Duo environment must be provided during the Duo environment configuration. See details below on how this is done.

3. The inner hashtable must have the following keys:

    1. **IntegrationKey** - The Duo integration key.
    2. **SecretKey/SecretKeyEncrypted** - The Duo secret key associated with the integration key. If the **SecretKey** key is used then the secret key is in plain text. If the **SecretKeyEncrypted** key is used then the secret key is a string representation of a standard *SecureString*. If both keys are used only the **SecretKeyEncrypted** key will be used.
    3. **ApiHostname** - The hostname of the API host used to process the API calls.

4. The inner hashtable can optionally have the following keys:

    1. **ProxyServer** - The hostname of the proxy server used to connect to Duo if a proxy server is required. All other proxy related keys will be ignored if this key is not present.
    2. **ProxyPort** - The port to use when connecting through the specified proxy server. Port 80 will be chosen if this key is not present.
    3. **ProxyBypassList** - The list of URIs that will not use the proxy. No bypass list will be used if this key is not present.
    4. **ProxyBypassOnLocal** - The switch to indicate whether shortname hosts will bypass the proxy. By default this will be set to false.
    5. **ProxyUsername** - The username used to authenticate to the specified proxy server. By default anonymous authentication is used.
    6. **ProxyPassword/ProxyPasswordEncrypted** - The password used to authenticate to the specified proxy server. If the **ProxyPassword** key is used then the password is in plain text. If the **ProxyPasswordEncrypted** key is used then the password is a string representation of a standard *SecureString*. If both keys are used only the **ProxyPasswordEncrypted** key will be used.
    7. **ProxyUseDefaultCredentials** - The switch to indicate whether or not to use Windows default credentials when authenticating to the specified proxy server. If this switch is given then the **ProxyUsername** and **ProxyPassword/ProxyPasswordEncrypted** keys are ignored. By default anonymous authentication is used.

Once this information has been given to the module you can make Duo API calls by specifying the environment you wish to use. If an environment is not provided during the call the default environment key will be used. The default environment key must be provided when configuring the Duo application environment details.

The Duo application environment details can be provided in one of the following ways:

- [DuoEnvironmentInfo.ps1 File](#DuoEnvFile) - Provide environment info prior to importing the module. This is the only method that will persist in new PowerShell sessions.
- [ArgumentList Configuration](#DuoEnvArgumentList) - Provide environment info during the module import process.
- [Set-DuoEnvironmentInfo](#DuoEnvArgumentList) - Provide environment info after the module has been imported.
- [Proxy Configuration](#Proxy) - Provide proxy server conifguration info after the environment info has already be configured.

##### <a name="DuoEnvFile"></a> Configure DuoEnvironmentInfo.ps1 File

Using the *DuoEnvironmentInfo.ps1* file that comes with the module is the easiest way to configure the module. It is also the only method that persists between PowerShell sessions. For details on the format of the data in this file see the above section: [Duo Environment Configuration](#DuoEnvConfig).

1. Open the module folder, then open the folder named *DuoEnvironmentInfo*.

2. Open the file named *DuoEnvironmentInfo.ps1*.

3. Fill in the fake values with your information. Add/Remove environments as needed.

4. Update the default environment key variable at the top to one of the environments in your hashtable.

5. Save file and import module.

When importing the module a check will be ran to ensure the hashtable is in the proper format as described in the section above.

##### <a name="DuoEnvArgumentList"></a> ArgumentList Configuration

You can pass in the Duo application environment details during the import of the module itself by using the `-ArgumentList` property of the `Import-Module` command to provide the hashtable and default environment key to the module. Specifying the environment details in this manner will override any info stored in the *DuoEnvironmentInfo.ps1* file mentioned in the above section.

Once the hashtable is stored in a variable you can pass the environment info and the default environment key to the module on import using the command below.

###### Example : Using the $DuoEnvironmentInfo hashtable above and specifying the environment set 'Test' as the default environment.

``` powershell
Import-Module Posh-DuoAPI -ArgumentList @($DuoEnvironmentInfo, 'Test')
```

##### <a name="SetDuoEnvInfo"></a> Set-DuoEnvironmentInfo Command

The module has a DuoEnvironmentInfo.ps1 file that comes with pre-filled in with fake values. This means that you can import the module without modifying the file or without specifying a configuration via the Import-Module -ArgumentList parameter. However, since the values are fake, you will not be able to successfully execute any API calls until it has been updated. At any point after importing the module you can change the current Duo environment configuration by using the `Set-DuoEnvironmentInfo` command and providing it a hashtable and default environment key as described in the above section ([Duo Environment Configuration](#DuoEnvConfig)). There is also a `Get-DuoEnvironmentInfo` that can be used to retrieve and view the current settings.

To set the Duo environment details at any time use the following command:

###### Example : Using the $DuoEnvironmentInfo hashtable above and specifying the environment set 'Test' as the default environment.

``` powershell
Set-DuoEnvironmentInfo -DuoEnvironmentInfo $DuoEnvironmentInfo -DuoDefaultEnv 'Test'
```

##### <a name="Proxy"></a> Proxy Server Configuration

By default this module will use the proxy settings from Internet Explorer for the current user. Therefore, it is typically not needed for you to manually configure the proxy settings for this module. However, if you are attempting to use this module as a user that does not have proxy settings in Internet Explorer configured (i.e. a service running as SYSTEM) and a proxy server is required to reach the Duo API servers, then you will need to configure the proxy settings for this module as described below.

Proxy server configuration information can be configured using any of the above methods for environment configuration by adding the proxy server info to the environment hashtable of each Duo application environment. For details on properly formatting the Duo application environment hashtable with proxy information see the above section: ([Duo Environment Configuration](#DuoEnvConfig)). You can also set the proxy server info at any time after the Duo application environment has been configured by using the `Set-DuoEnvironmentProxy` command.

To set the Duo environment proxy server details at any time use the following command (only *-ProxyServer* is required):

``` powershell
Set-DuoEnvironmentProxy -ProxyServer 'your-proxy-01.domain.local' -ProxyPort 8080 -ProxyBypassList @('*.domain.local', '*.otherdomain.local') -ProxyBypassOnLocal -ProxyUseDefaultCredentials -DuoEnv 'Test'
```

## <a name="Examples"></a> Examples

Once the module is imported and the Duo environment info has been configured as detailed in the section above ([Duo Environment Configuration](#DuoEnvConfig)), you can begin using the Duo commands to make Duo API calls. Below are a few examples.

###### Example 1 : Ping Duo API servers to ensure they are up and accepting API requests.

``` powershell
If (Test-DuoPing) {
    # Perform more Duo API calls.
} Else {
    Throw 'Duo servers are down.'
}
```

###### Example 2 : Verify the Duo integration key and secret key are validating against the Duo API host. Use the *Test* application environment.

``` powershell
If (Test-DuoCheckKeys -DuoEnv 'Test') {
    # Perform more Duo API calls.
} Else {
    Throw 'API keys are invalid.'
}
```

###### Example 3 : Authenticate a user.

``` powershell

# Get user device information and make sure the user is capable of logging in.
$preAuth = Get-DuoPreAuth -Username 'johndoe'

If (($preAuth.stat -eq 'OK') -and ($preAuth.response.result -eq 'auth')) {

    # Use Duo App Auto method which choose the best available method for the first available device.
    $auth = Get-DuoAuth -Username 'johndoe' -AuthFactorAuto -Device $preAuth.response.devices[0].device

    # Check authentication result.
    If (($auth.stat -eq 'OK') -and ($auth.response.result -eq 'allow')) {
        Write-Host "Success : $($auth.response.status_msg)"
    } Else {
        Write-Host "Failed : $($auth.response.status_msg)"
    }

}

```

###### Example 4 : Custom API call.

``` powershell
$auth = Invoke-DuoRequest -DuoEnv 'Prod' -Method 'POST' -Path '/auth/v2/auth' -Parameters @{
            'username' = 'johndoe'
            'factor' = 'push'
            'device' = 'auto'
            'display_username' = 'Johnathan Doe'
            'type' = 'My Special Login Request Type'
            'pushinfo' = 'from=PowerShellUsername&domain=company.org&Foo=Bar'
        }

If (($auth.stat -eq 'OK') -and ($auth.response.result -eq 'allow')) {
    Write-Host "Success : $($auth.response.status_msg)"
} Else {
    Write-Host "Failed : $($auth.response.status_msg)"
}
```

###### Example 5 : Custom API call that returns a byte array of the response.

``` powershell
# Get logo and return as byte array.
[byte[]]$rawLogoPngBytes = Invoke-DuoRequest -Path '/auth/v2/logo' -Method 'GET' -ReturnRawBytes

# Save bytes to PNG file.
$rawLogoPngBytes | Set-Content "C:\Temp\logo.png" -Encoding Byte
```