<#

    All public functions will be placed here.

#>

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

###################
## Duo Functions ##
###################

#region Duo Functions

#====================================================================================================================================================
#######################
## Invoke-DuoRequest ##
#######################

#region Invoke-DuoRequest

Function Invoke-DuoRequest {

    <#

        .SYNOPSIS

            Generates and sends a new Duo API request.

        .DESCRIPTION

            Generates and sends a new Duo API request based on the provided parameters. For details on what calls can be made please review the Duo documentation found at the following locations.

                Duo Admin API : https://duo.com/support/documentation/adminapi
                Duo Auth API  : https://duo.com/docs/authapi

        .PARAMETER Path

            The Duo API path for a given API call. This path should not include the API host but simply the path to the API resource.

            EX: '/auth/v2/auth'

        .PARAMETER Method

            The HTTP method by which to submit the Duo API call.

            EX: 'GET' or 'POST' or 'DELETE'

        .PARAMETER Parameters

            A hashtable which contains key/value pairs of each Duo API request parameter needed.

            EX: @{
                   username = 'janedoe'
                   exFieldWithSpaces = 'some value with spaces'
                 }

        .PARAMETER ReturnRawBytes

            If this switch is set, the response body to the Duo request will be returned as raw bytes. By default the response is converted from its native JSON format into a PSObject.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([Parameter(Mandatory)] [string]$Path,
          [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'DELETE')] [string]$Method,
          [hashtable]$Parameters,
          [switch]$ReturnRawBytes = $false,
          [ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    Write-Debug "Invoke-DuoRequest : Using Environment '$DuoEnv' : `n$($script:DuoEnvironmentInfo[$DuoEnv] | Out-String)"

    # Canonicalize all request parameters.
    $canonParams = Get-DuoCanonicalizeParameter -RequestParameters $Parameters

    # Setup the query string if needed.
    $query = ''
    If (($Method.ToUpper() -eq 'GET') -or ($Method.ToUpper() -eq 'DELETE')) {
        If ($Parameters.Count -gt 0) {
            $query = '?' + $canonParams
        }
    }

    # Add a leading slash to the path if not present.
    If ($Path -notmatch '^/') { $Path = '/' + $Path }

    # Build the URI.
    $uri = 'https://' + $script:DuoEnvironmentInfo[$DuoEnv].ApiHostname + $Path + $query

    # Build the Duo authorization header.
    $dateStr = Get-DuoRFC2822Date
    $authN = Get-DuoAuthorizationHeader -Path $Path -Method $Method -Date $dateStr -CanonicalizedParameters $canonParams -DuoEnv $DuoEnv

    $authHeaders = @{
        'X-Duo-Date' = $dateStr
        'Authorization' = $authN
    }

    # Send the request and check the response.
    $result = Send-DuoRequest -DuoEnv $DuoEnv -Method $Method -Uri $uri -AuthHeaders $authHeaders -CanonicalizedParameters $canonParams -ReturnRawBytes:$ReturnRawBytes

    Return $result

}

Export-ModuleMember -Function 'Invoke-DuoRequest'

#endregion Invoke-DuoRequest

#====================================================================================================================================================
############################
## Get-DuoEnvironmentInfo ##
############################

#region Get-DuoEnvironmentInfo

Function Get-DuoEnvironmentInfo {

    <#

        .SYNOPSIS

            Returns the current DuoEnvironmentInfo configuration.

        .DESCRIPTION

            Returns the current DuoEnvironmentInfo configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param()

    # Hashtables pass by reference. So we have to recreate/clone them to prevent the user from modifying the hashtable they are getting
    # and in turn modifying the hashtable stored in this module without a proper validation test being performed on it.
    $userEnvironmentInfo = @{}
    $DuoEnvironmentInfo.Keys | ForEach-Object { $userEnvironmentInfo[$_] = $DuoEnvironmentInfo[$_].Clone() }
    Return = $userEnvironmentInfo

}

Export-ModuleMember -Function 'Get-DuoEnvironmentInfo'

#endregion Get-DuoEnvironmentInfo

#====================================================================================================================================================
############################
## Set-DuoEnvironmentInfo ##
############################

#region Set-DuoEnvironmentInfo

Function Set-DuoEnvironmentInfo {

    <#

        .SYNOPSIS

            Sets the current DuoEnvironmentInfo configuration.

        .DESCRIPTION

            Sets the current DuoEnvironmentInfo configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

        .PARAMETER DuoEnvironmentInfo

            The new DuoEnvironmentInfo configuration you would like to set.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

        .PARAMETER DuoDefaultEnv

            The default environment to use in the specified DuoEnvironmentInfo configuration. If not specified the current default will remain unchanged.

    #>

    [CmdletBinding()]

    Param([Parameter(Mandatory)] [hashtable]$DuoEnvironmentInfo,
          [Parameter(Mandatory)] [string]$DuoDefaultEnv)

    # Save the old info in case we have to restore it.
    $oldInfo = $script:DuoEnvironmentInfo
    $oldDefault = $script:DuoDefaultEnv

    # Set the current environment info to the specified info.
    # Hashtables pass by reference. So we have to recreate/clone them to prevent the user from modifying the hashtable they passed in
    # and in turn modifying the hashtable stored in this module without a proper validation test being performed on it.
    $userEnvironmentInfo = @{}
    $DuoEnvironmentInfo.Keys | ForEach-Object { $userEnvironmentInfo[$_] = $DuoEnvironmentInfo[$_].Clone() }
    $script:DuoEnvironmentInfo = $userEnvironmentInfo
    $script:DuoDefaultEnv = $DuoDefaultEnv

    # Verify the info is correct.
    Try {
        Test-DuoEnvInfoFormat | Out-Null
    } Catch {
        # Something is wrong with the hashtable format or default environment. Restoring old values.
        $script:DuoEnvironmentInfo = $oldInfo
        $script:DuoDefaultEnv = $oldDefault
        Throw  # Retrhow error.
    }

}

Export-ModuleMember -Function 'Set-DuoEnvironmentInfo'

#endregion Set-DuoEnvironmentInfo

#====================================================================================================================================================
#############################
## Set-DuoEnvironmentProxy ##
#############################

#region Set-DuoEnvironmentProxy

Function Set-DuoEnvironmentProxy {

    <#

        .SYNOPSIS

            Sets the proxy server information for a given Duo environment configuration.

        .DESCRIPTION

            Sets the proxy server information for a given Duo environment configuration. The specified Duo configuration must already exist in the current configuration hashtable.

            For details on environment configurations and proxy settings please see https://github.com/The-New-Guy/Posh-DuoAPI.

        .PARAMETER UseSystemSettings

            If this switch is specified, the command will attempt to retrieve proxy settings from system and then assigns those settings to the specified Duo environment configuration. The system settings referenced here are typically set via the 'netsh winhttp' command context.

            NOTE: Depending on your proxy server configuration you may or may not still need to provide credentials when using the system settings or specify the UseDefaultCredentials switch.

        .PARAMETER Server

            The proxy server hostname that will be used to connect to Duo.

            This setting will be assigned to the specified Duo environment configuration.

        .PARAMETER Port

            The port used to connect to the proxy server.

            This setting will be assigned to the specified Duo environment configuration.

        .PARAMETER BypassList

            The list of URIs that will not use the proxy server.

            This setting will be assigned to the specified Duo environment configuration.

        .PARAMETER BypassOnLocal

            The switch to indicate whether shortname hosts will bypass the proxy. By default this will be set to false.

            This setting will be assigned to the specified Duo environment configuration.

        .PARAMETER Credentials

            The credentials to be used when authenticating to the proxy server.

            This setting will be assigned to the specified Duo environment configuration.

        .PARAMETER UseDefaultCredentials

            The switch to indicate whether or not to use Windows default credentials when authenticating to the proxy server. By default this will be set to false.

            This setting will be assigned to the specified Duo environment configuration.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([Parameter(Mandatory, ParameterSetName = 'UseSystemSettings')] [switch]$UseSystemSettings,
          [Parameter(Mandatory, ParameterSetName = 'ManualEntry')] [string]$Server,
          [Parameter(ParameterSetName = 'ManualEntry')] [int]$Port,
          [Parameter(ParameterSetName = 'ManualEntry')] [array]$BypassList,
          [Parameter(ParameterSetName = 'ManualEntry')] [switch]$BypassOnLocal,
          [Parameter(ParameterSetName = 'ManualEntry')] [Parameter(ParameterSetName = 'UseSystemSettings')] [pscredential]$Credentials,
          [Parameter(ParameterSetName = 'ManualEntry')] [Parameter(ParameterSetName = 'UseSystemSettings')] [switch]$UseDefaultCredentials,
          [ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    # Save the old info in case we have to restore it.
    $oldEnvInfo = $script:DuoEnvironmentInfo[$DuoEnv]

    If ($PSCmdlet.ParameterSetName -eq 'UseSystemSettings') {
        $systemProxy = Get-DuoSystemProxy

        If (($systemProxy -ne $null) -and ($systemProxy.ProxyEnabled)) {
            $script:DuoEnvironmentInfo[$DuoEnv].ProxyServer = ($systemProxy.ProxyServer -split ':')[0]
            If (($systemProxy.ProxyServer -split ':')[1] -ne $null) { $script:DuoEnvironmentInfo[$DuoEnv].ProxyPort = ($systemProxy.ProxyServer -split ':')[1] }
            If ($systemProxy.BypassList -match '<local>') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyBypassOnLocal = $true }
            If ($systemProxy.BypassList.Length -gt 0) { $script:DuoEnvironmentInfo[$DuoEnv].ProxyBypassList = ($systemProxy.BypassList -replace '<local>;','') -split ';' }
            If ($PSBoundParameters.Keys -contains 'Credentials') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyUsername = $Credentials.UserName; $script:DuoEnvironmentInfo[$DuoEnv].ProxyPasswordEncrypted = ConvertFrom-SecureString -SecureString $Credentials.Password }
            If ($PSBoundParameters.Keys -contains 'UseDefaultCredentials') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyUseDefaultCredentials = [bool]$UseDefaultCredentials }
        }
    } ElseIf ($PSCmdlet.ParameterSetName -eq 'ManualEntry') {

        $script:DuoEnvironmentInfo[$DuoEnv].ProxyServer = $Server
        If ($PSBoundParameters.Keys -contains 'Port') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyPort = $Port }
        If ($PSBoundParameters.Keys -contains 'BypassList') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyBypassList = $BypassList }
        If ($PSBoundParameters.Keys -contains 'BypassOnLocal') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyBypassOnLocal = [bool]$BypassOnLocal }
        If ($PSBoundParameters.Keys -contains 'Credentials') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyUsername = $Credentials.UserName; $script:DuoEnvironmentInfo[$DuoEnv].ProxyPasswordEncrypted = ConvertFrom-SecureString -SecureString $Credentials.Password }
        If ($PSBoundParameters.Keys -contains 'UseDefaultCredentials') { $script:DuoEnvironmentInfo[$DuoEnv].ProxyUseDefaultCredentials = [bool]$UseDefaultCredentials }

        # Verify the info is in a correct format.
        Try {
            Test-DuoEnvInfoFormat | Out-Null
        } Catch {
            # Something is wrong with the hashtable format or default environment. Restoring old values.
            $script:DuoEnvironmentInfo[$DuoEnv] = $oldEnvInfo
            Throw  # Retrhow error.
        }

    }

}

Export-ModuleMember -Function 'Set-DuoEnvironmentProxy'

#endregion Set-DuoEnvironmentProxy

#endregion Duo Functions

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

############################
## Duo Auth API Functions ##
############################

#region Duo Auth API Functions

#====================================================================================================================================================
##################
## Test-DuoPing ##
##################

#region Test-DuoPing

Function Test-DuoPing {

    <#

        .SYNOPSIS

            Performs a "liveness check" that can be called to verify that Duo is up before trying to call other endpoints.

        .DESCRIPTION

            Performs a "liveness check" that can be called to verify that Duo is up before trying to call other endpoints.

            For details on a Duo API Ping endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    $result = Invoke-DuoRequest -DuoEnv $DuoEnv -Method 'GET' -Path '/auth/v2/ping'

    If ($result.stat -eq 'OK') {
        Return $true
    } Else {
        Return $false
    }

}

Export-ModuleMember -Function 'Test-DuoPing'

#endregion Test-DuoPing

#====================================================================================================================================================
#######################
## Test-DuoCheckKeys ##
#######################

#region Test-DuoCheckKeys

Function Test-DuoCheckKeys {

    <#

        .SYNOPSIS

            Checks to ensure that the Duo Integration Key and associated Secret Key are valid and active in Duo.

        .DESCRIPTION

            Checks to ensure that the Duo Integration Key and associated Secret Key are valid and active in Duo.

            For details on a Duo API Check endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    $result = Invoke-DuoRequest -DuoEnv $DuoEnv -Method 'GET' -Path '/auth/v2/check'

    If ($result.stat -eq 'OK') {
        Return $true
    } Else {
        Return $false
    }

}

Export-ModuleMember -Function 'Test-DuoCheckKeys'

#endregion Test-DuoCheckKeys

#====================================================================================================================================================
#################
## Get-DuoLogo ##
#################

#region Get-DuoLogo

Function Get-DuoLogo {

    <#

        .SYNOPSIS

            Retrieves the logo provided to Duo for your organization.

        .DESCRIPTION

            Retrieves the logo provided to Duo for your organization.

            For details on a Duo API Logo endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER FilePath

            The path to the file that the logo should be saved to. If no Filepath is provided then a file called "logo.png" will be saved in the current directory. The logo comes back in a PNG format and therfore should be saved with a PNG extension.

        .PARAMETER ReturnRawBytes

            If this switch is set, the logo will be returned as raw bytes.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([string]$FilePath = "$((Get-Location).ProviderPath)\logo.png",
          [switch]$ReturnRawBytes,
          [ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    # Get the logo as bytes.
    [byte[]]$logoBytes = Invoke-DuoRequest -DuoEnv $DuoEnv -Path '/auth/v2/logo' -Method 'GET' -ReturnRawBytes

    If ($ReturnRawBytes) {

        Return $logoBytes

    } Else {

        If (Test-Path (Split-Path $FilePath -Parent)) { $logoBytes | Set-Content $FilePath -Encoding Byte }
        Else { Throw "The file path provide is not valid: $FilePath" }

        Write-Verbose "Logo saved to the following location: $FilePath"

    }

}

Export-ModuleMember -Function 'Get-DuoLogo'

#endregion Get-DuoLogo

#====================================================================================================================================================
###################
## Get-DuoEnroll ##
###################

#region Get-DuoEnroll

Function Get-DuoEnroll {

    <#

        .SYNOPSIS

            Provides a programmatic way to enroll new users with Duo two-factor authentication.

        .DESCRIPTION

            Provides a programmatic way to enroll new users with Duo two-factor authentication. It creates the user in Duo and returns a code (as a barcode image) that Duo Mobile can scan with its built-in camera. Scanning the barcode adds the user's account to the app so that they receive and respond to Duo Push login requests.

            For details on a Duo API Enroll endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER Username

            Username for the created user. If not given, a random username will be assigned and returned.

        .PARAMETER ValidSeconds

            Seconds for which the activation code will remain valid. Default: 86400 (one day).

        .PARAMETER BarcodeDownload

            During an enroll request, one of the fields returned by Duo is a URL for a QR style barcode that can be used by the Duo app to enroll a user. If this switch is used that QR barcode will be automatically downloaded to a file.

        .PARAMETER BarcodeFilePath

            If the BarcodeDownload switch is provided, this parameter will specify where the QR barcode is saved. If not provided the default will be a file called "barcode.png" in the current directory.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([string]$Username,
          [ValidateScript({ $_ -ge 0 })] [int]$ValidSeconds,
          [switch]$BarcodeDownload,
          [string]$BarcodeFilePath = "$((Get-Location).ProviderPath)\barcode.png",
          [ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    # Build parameters.
    $params = @{}

    If ($Username) { $params.username = $Username }
    If ($ValidSeconds) { $params.valid_secs = $ValidSeconds }

    $resp = Invoke-DuoRequest -DuoEnv $DuoEnv -Path '/auth/v2/enroll' -Method 'POST' -Parameters $params

    If ($BarcodeDownload) {

        If (Test-Path (Split-Path $BarcodeFilePath -Parent)) { Invoke-WebRequest -Uri $resp.response.activation_barcode -OutFile $BarcodeFilePath }
        Else { Throw "The file path provide is not valid: $BarcodeFilePath" }

        Write-Verbose "Logo saved to the following location: $BarcodeFilePath"

    }

    Return $resp

}

Export-ModuleMember -Function 'Get-DuoEnroll'

#endregion Get-DuoEnroll

#====================================================================================================================================================
#########################
## Get-DuoEnrollStatus ##
#########################

#region Get-DuoEnrollStatus

Function Get-DuoEnrollStatus {

    <#

        .SYNOPSIS

            Check whether a user has completed enrollment.

        .DESCRIPTION

            Check whether a user has completed enrollment.

            For details on a Duo API EnrollStatus endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER UserId

            Permanent, unique identifier for the user in Duo.

        .PARAMETER ActivationCode

            Activation code, as returned from Get-DuoEnroll.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([Parameter(Mandatory)] [string]$UserId,
          [Parameter(Mandatory)] [string]$ActivationCode,
          [ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    # Wait for authentication status update.
    $response = Invoke-DuoRequest -DuoEnv $DuoEnv -Path '/auth/v2/enroll_status' -Method 'POST' -Parameters @{ user_id = $UserId; activation_code = $ActivationCode }

    Return $response

}

Export-ModuleMember -Function 'Get-DuoEnrollStatus'

#endregion Get-DuoEnrollStatus

#====================================================================================================================================================
####################
## Get-DuoPreAuth ##
####################

#region Get-DuoPreAuth

Function Get-DuoPreAuth {

    <#

        .SYNOPSIS

            Determines whether a user is authorized to log in, and (if so) returns the user's available authentication factors.

        .DESCRIPTION

            Determines whether a user is authorized to log in, and (if so) returns the user's available authentication factors.

            For details on a Duo API Preauth endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER UserId

            Permanent, unique identifier for the user as generated by Duo upon user creation (e.g. DUYHV6TJBC3O4RITS1WC).

            Either a UserId or Username must be specified.

        .PARAMETER Username

            Unique identifier for the user that is commonly specified by your application during user creation (e.g. username or username@domain.com).

            Either a UserId or Username must be specified.

        .PARAMETER IPAddress

            The IP address of the user to be authenticated, in dotted quad format. This will cause an "allow" response to be sent if appropriate for requests from a trusted network.

            This is an optional parameter.

        .PARAMETER TrustedDeviceToken

            If the TrustedDeviceToken switch is given and the Trusted devices option is enabled in the Duo Admin Panel, return an "allow" response for the period of time a device may be remembered as set by the Duo administrator.

            This is an optional parameter.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding(DefaultParameterSetName = 'Username')]

    Param([Parameter(Mandatory, ParameterSetName = 'UserId')] [string]$UserId,
          [Parameter(Mandatory, ParameterSetName = 'Username')] [string]$Username,
          [ValidateScript({ $_ -match [IPAddress]$_ })] [string]$IPAddress,
          [switch]$TrustedDeviceToken,
          [ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    # Build list of parameters.
    $params = @{}

    If ($PSCmdlet.ParameterSetName -eq 'Username') { $params.username = $Username }
    ElseIf ($PSCmdlet.ParameterSetName -eq 'UserId') { $params.user_id = $UserId }

    If ($IPAddress) { $params.ipaddr = $IPAddress }

    If ($TrustedDeviceToken) { $params.trusted_device_token = $TrustedDeviceToken }

    # Invoke the API call.
    $response = Invoke-DuoRequest -DuoEnv $DuoEnv -Path '/auth/v2/preauth' -Method 'POST' -Parameters $params

    Return $response

}

Export-ModuleMember -Function 'Get-DuoPreAuth'

#endregion Get-DuoPreAuth

#====================================================================================================================================================
#################
## Get-DuoAuth ##
#################

#region Get-DuoAuth

Function Get-DuoAuth {

    <#

        .SYNOPSIS

            Performs second-factor authentication for a user by sending a push notification to the user's smartphone app, verifying a passcode, or placing a phone call. It is also used to send the user a new batch of passcodes via SMS.

        .DESCRIPTION

            Performs second-factor authentication for a user by sending a push notification to the user's smartphone app, verifying a passcode, or placing a phone call. It is also used to send the user a new batch of passcodes via SMS.

            For details on a Duo API Auth endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER UserId

            Permanent, unique identifier for the user as generated by Duo upon user creation (e.g. DUYHV6TJBC3O4RITS1WC).

            Either a UserId or Username must be specified.

        .PARAMETER Username

            Unique identifier for the user that is commonly specified by your application during user creation (e.g. username or username@domain.com).

            Either a UserId or Username must be specified.

        .PARAMETER AuthFactorAuto

            Use the out-of-band factor (push or phone) recommended by Duo as the best for the user's devices.

            When specifying this switch the following additional parameters will be available. Please see the corresponding parameter help section for more details:

                Device : Required
                Pushtype : Optional (Only used if Push is chosen as the optimal factor method)
                DispalyUsername : Optional (Only used if Push is chosen as the optimal factor method)
                PushInfo : Optional (Only used if Push is chosen as the optimal factor method)

        .PARAMETER AuthFactorPush

            Authenticate the user with Duo Push.

            When specifying this switch the following additional parameters will be available. Please see the corresponding parameter help section for more details:

                Device : Required
                Pushtype : Optional
                DispalyUsername : Optional
                PushInfo : Optional

        .PARAMETER AuthFactorPasscode

            Authenticate the user with a passcode (from Duo Mobile, SMS, hardware token, or bypass code).

            When specifying this switch the following additional parameters will be available. Please see the corresponding parameter help section for more details:

                PasscodeValue : Required

        .PARAMETER AuthFactorSms

            Send a new batch of SMS passcodes to the user. Note that this will not actually authenticate the user (it will automatically return "deny"). Thus, if the user elects to do this then you should re-prompt to authenticate after the call has completed.

            When specifying this switch the following additional parameters will be available. Please see the corresponding parameter help section for more details:

                Device : Required

        .PARAMETER AuthFactorPhone

            Authenticate the user with phone callback.

            When specifying this switch the following additional parameters will be available. Please see the corresponding parameter help section for more details:

                Device : Required

        .PARAMETER PushType

            This string is displayed in the Duo Mobile app before the word "request". The default is "Login", so the phrase "Login request" appears in the push notification text and on the request details screen. You may want to specify "Transaction", "Transfer", etc.

            This is an optional parameter only available with the AuthFactorAuto and AuthFactorPush switches.

            NOTE: The above description was straight from the Duo Auth API documentation. However, in my experience the value you provide for this parameter will be the entire string displayed. The word "request" will not be automatically appended to it. The one exception is the word "Login" which will be automaticatlly appended by the word "request" and is the default. This may be a bug or maybe inaccurate documentation.

        .PARAMETER DisplayUsername

            String to display in Duo Mobile in place of the user's Duo username.

            This is an optional parameter only available with the AuthFactorAuto and AuthFactorPush switches.

        .PARAMETER PushInfo

            A set of URL-encoded key/value pairs with additional contextual information associated with this authentication attempt. The Duo Mobile app will display this information to the user.

            For example: from=login%20portal&domain=example.com

            The URL-encoded string's total length must be less than 20,000 bytes.

            This is an optional parameter only available with the AuthFactorAuto and AuthFactorPush switches.

        .PARAMETER PasscodeValue

            Passcode entered by the user.

            This is a mandatory parameter only available with the AuthFactorPasscode switch.

        .PARAMETER Device

            ID of the device to call. This device must have the "phone" capability.

            You may also specify "auto" to use the first of the user's devices with the "phone" capability.

            This is a mandatory parameter only available with the AuthFactorAuto, AuthFactorPush, AuthFactorSms and AuthFactorPhone switches.

        .PARAMETER IPAddress

            The IP address of the user to be authenticated, in dotted quad format. This will cause an "allow" response to be sent if appropriate for requests from a trusted network.

            This is an optional parameter.

        .PARAMETER Async

            If this switch is not provided, then the Duo API host will only return a response when the authentication process has completed. If, however, this switch is provided, then the Duo API host will immediately return a transaction ID, and your application will need to subsequently query the Get-DuoAuthStatus command to get the status (and eventually the result) of the authentication process.

            If this switch is provided, then your application will be able to retrieve real-time status updates from the authentication process, rather than receiving no information until the process is complete.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding(DefaultParameterSetName = 'UsernamePush')]

    Param(

        # Every auth attempt must have either UserId or Username but not both.
        # Same is true for the 5 possible factor methods (must have one and only one allowed).
        # Each factor method has a different set of associated parameters.
        # 2 x 5 = 10 parameter sets. 5 for each user identification parameter.

        # UserId
        [Parameter(Mandatory, ParameterSetName = 'UserIdAuto')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPush')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPasscode')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdSms')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPhone')]
        [string]$UserId,

        # Username
        [Parameter(Mandatory, ParameterSetName = 'UsernameAuto')]
        [Parameter(Mandatory, ParameterSetName = 'UsernamePush')]
        [Parameter(Mandatory, ParameterSetName = 'UsernamePasscode')]
        [Parameter(Mandatory, ParameterSetName = 'UsernameSms')]
        [Parameter(Mandatory, ParameterSetName = 'UsernamePhone')]
        [string]$Username,

        # Auto pick a factor method.
        [Parameter(Mandatory, ParameterSetName = 'UsernameAuto')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdAuto')]
        [switch]$AuthFactorAuto,

        # Push factor method and any Push associated parameters.
        [Parameter(Mandatory, ParameterSetName = 'UsernamePush')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPush')]
        [switch]$AuthFactorPush,

        # If factor method is Auto and a Push capable device is found, these parameters if present will be used as well.
        [Parameter(ParameterSetName = 'UsernamePush')]
        [Parameter(ParameterSetName = 'UserIdPush')]
        [Parameter(ParameterSetName = 'UsernameAuto')]
        [Parameter(ParameterSetName = 'UserIdAuto')]
        [string]$PushType,

        [Parameter(ParameterSetName = 'UsernamePush')]
        [Parameter(ParameterSetName = 'UserIdPush')]
        [Parameter(ParameterSetName = 'UsernameAuto')]
        [Parameter(ParameterSetName = 'UserIdAuto')]
        [string]$DisplayUsername,

        [Parameter(ParameterSetName = 'UsernamePush')]
        [Parameter(ParameterSetName = 'UserIdPush')]
        [Parameter(ParameterSetName = 'UsernameAuto')]
        [Parameter(ParameterSetName = 'UserIdAuto')]
        [string]$PushInfo,

        # Passcode factor method and any Passcode associated parameters.
        [Parameter(Mandatory, ParameterSetName = 'UsernamePasscode')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPasscode')]
        [switch]$AuthFactorPasscode,

        [Parameter(Mandatory, ParameterSetName = 'UsernamePasscode')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPasscode')]
        [string]$PasscodeValue,

        # Sms factor method.
        [Parameter(Mandatory, ParameterSetName = 'UsernameSms')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdSms')]
        [switch]$AuthFactorSms,

        # Phone factor method.
        [Parameter(Mandatory, ParameterSetName = 'UsernamePhone')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPhone')]
        [switch]$AuthFactorPhone,

        # Device parameter is used by Auto, Push, Sms and Phone.
        [Parameter(Mandatory, ParameterSetName = 'UsernameAuto')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdAuto')]
        [Parameter(Mandatory, ParameterSetName = 'UsernamePush')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPush')]
        [Parameter(Mandatory, ParameterSetName = 'UsernameSms')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdSms')]
        [Parameter(Mandatory, ParameterSetName = 'UsernamePhone')]
        [Parameter(Mandatory, ParameterSetName = 'UserIdPhone')]
        [string]$Device,

        # All parameter sets (default)
        [ValidateScript({ $_ -match [IPAddress]$_ })]
        [string]$IPAddress,

        [switch]$Async,

        [ValidateScript({ Test-DuoEnv -DuoEnv $_ })]
        [string]$DuoEnv = $script:DuoDefaultEnv
    )

    # Build list of parameters.
    $params = @{}

    Write-Debug "Get-DuoAuth : Parameter Set : `n$($PSCmdlet.ParameterSetName)"

    # Add appropriate user identity parameter.
    If ($PSCmdlet.ParameterSetName -match 'UserId') { $params.user_id = $UserId }
    ElseIf ($PSCmdlet.ParameterSetName -match 'Username') { $params.username = $Username }

    # Add appropriate authentication factor method.
    If ($PSCmdlet.ParameterSetName -match 'Auto') {

        $params.factor = 'auto'
        $params.device = $Device
        If ($PushType) { $params.type = $PushType }
        If ($DisplayUsername) { $params.display_username = $DisplayUsername }
        If ($PushInfo) { $params.pushinfo = $PushInfo }

    } ElseIf ($PSCmdlet.ParameterSetName -match 'Push') {

        $params.factor = 'push'
        $params.device = $Device
        If ($PushType) { $params.type = $PushType }
        If ($DisplayUsername) { $params.display_username = $DisplayUsername }
        If ($PushInfo) { $params.pushinfo = $PushInfo }

    } ElseIf ($PSCmdlet.ParameterSetName -match 'Passcode') {

        $params.factor = 'passcode'
        $params.passcode = $PasscodeValue

    } ElseIf ($PSCmdlet.ParameterSetName -match 'Sms') {

        $params.factor = 'sms'
        $params.device = $Device

    } ElseIf ($PSCmdlet.ParameterSetName -match 'Phone') {

        $params.factor = 'phone'
        $params.device = $Device

    }

    If ($IPAddress) { $params.ipaddr = $IPAddress }

    If ($Async) { $params.async = '1' }

    Write-Debug "Get-DuoAuth : Parameters : `n$($params | Out-String)"

    # Invoke the API call.
    $response = Invoke-DuoRequest -DuoEnv $DuoEnv -Path '/auth/v2/auth' -Method 'POST' -Parameters $params

    Return $response

}

Export-ModuleMember -Function 'Get-DuoAuth'

#endregion Get-DuoAuth

#====================================================================================================================================================
#######################
## Get-DuoAuthStatus ##
#######################

#region Get-DuoAuthStatus

Function Get-DuoAuthStatus {

    <#

        .SYNOPSIS

            Retrieves the logo provided to Duo for your organization.

        .DESCRIPTION

            Performs a "long-poll" for the next status update from the authentication process for a given transaction. That is to say, if no status update is available at the time the request is sent, it will wait until there is an update before returning a response.

            For details on a Duo API Auth_Status endpoint and its response format please review the Duo documentation found at the following locations.

                Duo Auth API : https://duo.com/docs/authapi

        .PARAMETER TransactionId

            The transaction ID of the authentication attempt, as returned by the Get-DuoAuth command.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([Parameter(Mandatory)] [string]$TransactionId,
          [ValidateScript({ Test-DuoEnv -DuoEnv $_ })] [string]$DuoEnv = $script:DuoDefaultEnv)

    # Wait for authentication status update.
    $response = Invoke-DuoRequest -DuoEnv $DuoEnv -Path '/auth/v2/auth_status' -Method 'GET' -Parameters @{ txid = $TransactionId }

    Return $response

}

Export-ModuleMember -Function 'Get-DuoAuthStatus'

#endregion Get-DuoAuthStatus

#endregion Duo Auth API Functions

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#############################
## Duo Admin API Functions ##
#############################

#region Duo Admin API Functions

#endregion Duo Admin API Functions

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>