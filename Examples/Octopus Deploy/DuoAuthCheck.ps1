<#

    Last Modified Date: 04/13/2017

    This is an example of an Octopus Deploy script that can be used to perform Duo Authentications as part of a Deployment
    Process Step. Please note that this script was designed to run as part of an Octopus Deploy script template and therefore
    requires a number of Octopus Deploy parameters be passed in to the script. The DuoAuthCheck.json file located in the same
    directory is an example of an exported Octopus Deploy script template that uses this code. It is recommended you import the
    DuoAuthCheck.json file into Octopus Deploy as a script template as the Octopus Deploy parameters will already be setup.

    This requires that the project has the following required variables passed into the script template.

        DuoApiHostname
        DuoIntegrationKey
        DuoSecretKey OR DuoSecretEncKey
        DuoUsername

    The following optional parameters can also be passed into the script template.

        DuoPushType
        DuoPushInfo
        DuoDisplayUsername

    The following optional proxy parameters can also be passed into the script template.

        DuoProxyServer
        DuoProxyPort
        DuoProxyBypassList
        DuoProxyBypassOnLocal
        DuoProxyUseDefaultCredentials
        DuoProxyUsername
        DuoProxyPassword or DuoProxyPasswordEncrypted

    NOTE: For those reviewing this file just to see an example of the Posh-DuoAPI module, you may want to skip past the
          parameter checks and go straight to the "Duo Authentication" section below.

#>

# Check if we are running this from Octopus Deploy or testing with it manually.
# NOTE: If testing manually, you will need to change the information below to the appropriate values.
If (-not ($OctopusParameters)) {
    $OctopusParameters = @{
        # Duo API Info.
        DuoUsername = 'janedoe'
        DuoApiHostname = 'api-nnnnnxnx.duosecurity.com'
        DuoIntegrationKey = 'DIxxxxxxxxxxxxxxxxxx'
        #DuoSecretKey = 'YourSecretsHere'
        # --OR--
        DuoSecretEncKey = 'Big long protected SecureString represented as a string on 1 line here'

        # Optional parameters.
        DuoPushType = 'Deployment Request'
        DuoPushInfo = 'Project=Testing&Foo=Bar'
        DuoDisplayUsername = 'Jane Doe'
    }
}

# Get Octopus Deploy parameters. These are required.
If ($OctopusParameters['DuoApiHostname']) { $apiHost = $OctopusParameters['DuoApiHostname'] }
Else { Throw 'Must provide a Duo API Hostname parameter.'}

If ($OctopusParameters['DuoIntegrationKey']) { $apiIntKey = $OctopusParameters['DuoIntegrationKey'] }
Else { Throw 'Must provide a Duo API Integration Key parameter.'}

If ($OctopusParameters['DuoSecretKey']) { $apiSecretKey = $OctopusParameters['DuoSecretKey']; $secretKeyKeyname = 'SecretKey' }
ElseIf ($OctopusParameters['DuoSecretEncKey']) { $apiSecretKey = $OctopusParameters['DuoSecretEncKey']; $secretKeyKeyname = 'SecretKeyEncrypted' }
Else { Throw 'Must provide either a Duo API Secret Key or a Duo API Secret Key Encrypted parameter.'}

# Note: Some organizations require the domain suffix with the username (or full UPN). Others require just the username.
#       Modify the line below to not split at the '@' sign if you need the full UPN.
If ($OctopusParameters['DuoUsername']) { $username = ($OctopusParameters['DuoUsername'] -split '@')[0] }
Else { Throw 'Must provide a username.' }

# These Octopus Deploy parameters are optional.
$OptionalParams = @{}
If ($OctopusParameters['DuoPushType']) { $OptionalParams['PushType'] = $OctopusParameters['DuoPushType'] }
If ($OctopusParameters['DuoPushInfo']) { $OptionalParams['PushInfo'] = $OctopusParameters['DuoPushInfo'] }
If ($OctopusParameters['DuoDisplayUsername']) { $OptionalParams['DisplayUsername'] = $OctopusParameters['DuoDisplayUsername'] }

# These Octopus Deploy parameters are optional.
$ProxyParams = @{}
If ($OctopusParameters['DuoProxyServer']) { $ProxyParams['ProxyServer'] = $OctopusParameters['DuoProxyServer'] }
If ($OctopusParameters['DuoProxyPort']) { $ProxyParams['ProxyPort'] = $OctopusParameters['DuoProxyPort'] }
If ($OctopusParameters['DuoProxyBypassList']) { $ProxyParams['ProxyBypassList'] = $OctopusParameters['DuoProxyBypassList'] -split ',' }
If ($OctopusParameters['DuoProxyBypassOnLocal'] -eq 'True') { $ProxyParams['ProxyBypassOnLocal'] = $true }
If ($OctopusParameters['DuoProxyUseDefaultCredentials'] -eq 'True') { $ProxyParams['ProxyUseDefaultCredentials'] = $true }
If ($OctopusParameters['DuoProxyUsername']) { $ProxyParams['ProxyUsername'] = $OctopusParameters['DuoProxyUsername'] }
If ($OctopusParameters['DuoProxyPassword']) { $ProxyParams['ProxyPassword'] = $OctopusParameters['DuoProxyPassword'] }
ElseIf ($OctopusParameters['DuoProxyPasswordEncrypted']) { $ProxyParams['ProxyPasswordEncrypted'] = $OctopusParameters['DuoProxyPasswordEncrypted'] }

# Verify the proxy parameters make sense.

# If no proxy server exist then there should be no other proxy parameters given.
If (($ProxyParams['ProxyServer'] -eq $null) -and ($ProxyParams.Keys.Count -gt 0)) { Throw 'Cannont set proxy parameters if no proxy server is specified.' }

# If proxy server does exist, check other proxy parameters for validity.
If ($ProxyParams['ProxyServer']) {

    # If Proxy username is given then there must be a proxy password.
    If (($ProxyParams['ProxyUsername']) -and ($ProxyParams['ProxyPassword'] -eq $null) -and ($ProxyParams['ProxyPasswordEncrypted'] -eq $null)) {
        Throw 'A proxy password must be provided with the proxy username.'
    }

}

# Output variable values for Octopus Deploy log.
Write-Output "API Hostname : $apiHost"
Write-Output "API Integration Key : $apiIntKey"
Write-Output 'API Secret Key : Secret key is not null'  # Obviously don't want to display this in the log.
Write-Output "User : $username"
Write-Output "Optional Parameters : `n$($OptionalParams | Out-String)"
Write-Output "Proxy Parameters : `n$($ProxyParams.Clone() | Foreach-Object { $_.Remove('ProxyPassword'); $_.Remove('ProxyPasswordEncrypted'); $_ } | Out-String)"

######################
# Duo Authentication #
######################

# Build required Duo API envrionment information table.
$duoEnv = @{

    Env = @{

        ApiHostname = $apiHost
        IntegrationKey = $apiIntKey
        $secretKeyKeyname = $apiSecretKey

    }

}

# Add proxy server parameters.
Foreach ($key In $ProxyParams.Keys) { $duoEnv['Env'].$key = $ProxyParams[$key] }

# Is authentication successful?
$AuthSuccess = $false

# Import module.
Import-Module Posh-DuoAPI -ArgumentList $duoEnv, 'Env'

# Verify Duo API host is up and provided keys are valid.
If (-not (Test-DuoPing)) { Throw "Duo API host is down : $apiHost" }
If (-not (Test-DuoCheckKeys)) { Throw 'Provided keys do not appear to be valid.' }

# Check if user is enrolled and can authenticate with Duo if needed.
Write-Output 'Performing pre-authentication and retrieving list of available devices...'
$preAuth = Get-DuoPreAuth -Username $username

If (($preAuth.stat -eq 'OK') -and ($preAuth.response.result -eq 'auth')) {
    $shouldAuth = $true
} ElseIf (($preAuth.stat -eq 'OK') -and ($preAuth.response.result -eq 'allow')) {
    $shouldAuth = $false
    $AuthSuccess = $true  # User is allowed to bypass authentication.
} ElseIf (($preAuth.stat -eq 'OK') -and (($preAuth.response.result -eq 'deny') -or ($preAuth.response.result -eq 'enroll'))) {
    Throw $preAuth.response.status_msg
} ElseIf ($preAuth.stat -eq 'FAIL') {
    Throw ($preAuth.code + ' : ' + $preAuth.message + ' : ' + $preAuth.message_detail)
}

# Perform Duo authentication.
If ($shouldAuth) {

    # Try to find a registered device that does not require a passcode to be entered.
    # Basically, if it is a phone and has more than just mobile_otp as a possible method.
    $deviceId = $null
    Foreach ($dev In $preAuth.response.devices) {

        # Get device id.
        If ($dev.type -eq 'phone') {
            If (($dev.capabilities.Contains('mobile_otp')) -and ($dev.capabilities.Count -gt 1)) { $deviceId = $dev.device }
            ElseIf ((-not $dev.capabilities.Contains('mobile_otp')) -and ($dev.capabilities.Count -gt 0)) { $deviceId = $dev.device }
        }

        # Prompt user for authentication via their registered device.
        If ($deviceId) {
            Write-Output "Perfomring authentication via device: $deviceId"
            $auth = Get-DuoAuth -Username $username -AuthFactorAuto -Device $deviceId @OptionalParams

            If (($auth.stat -eq 'OK') -and ($auth.response.result -eq 'allow')) {
                $AuthSuccess = $true
            } ElseIf (($auth.stat -eq 'OK') -and ($auth.response.result -eq 'deny')) {
                Throw $auth.response.status_msg
            } ElseIf ($auth.stat -eq 'FAIL') {
                Throw ($auth.code + ' : ' + $auth.message + ' : ' + $auth.message_detail)
            }

            # Only need to do this for one device so break out of the loop here.
            Break

        } Else {
            Throw 'Error retrieving a registered device.'
        }

    }

}

# Is authentication successful?
# If not we likely threw an error above but just in case let's check.
If ($AuthSuccess) {
    Write-Output 'Authencation Successful.'
} Else {
    Throw 'Authentication Failed.'
}