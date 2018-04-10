<#

    All private functions will be placed here.

#>

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

##########################
## Duo Helper Functions ##
##########################

#region Duo Helper Functions

#====================================================================================================================================================
#####################
## Send-DuoRequest ##
#####################

#region Send-DuoRequest

# This function is called by the public command Invoke-DuoRequest to create and send the actual HTTP request to Duo.
# It does this after Invoke-DuoRequest has built the headers and canonicalized the request parameters.

Function Send-DuoRequest {

    <#

        .SYNOPSIS

            Sends a Duo API request call to the API host and returns the response.

        .DESCRIPTION

            Sends a Duo API request call to the API host and returns the response.

        .PARAMETER Method

            The HTTP method by which to submit the Duo API call.

            EX: 'GET' or 'POST' or 'DELETE'

        .PARAMETER Uri

            The full URI for the Duo API host and request resource.

            EX: 'https://api-nnnnnxnx.duosecurity.com/auth/v2/auth'

        .PARAMETER AuthHeaders

            The Duo specific Authorization header needed that has been signed and is ready to be sent in the reuqest header.

            Please see the help documentation for the Get-DuoAuthorizationHeader command for details.

        .PARAMETER CanonicalizedParameters

            A string representing all of the parameters being sent in the Duo API call which have been canonicalized as a standard URL-encoded string.

            NOTE: Duo does have some special handling of the URL-encoded parameters which is specified here: https://duo.com/docs/authapi#base-url
                  You can also use the Get-DuoCanonicalizeParameter internal module function to canonicalize the parameters according to Duo's restrictions.

        .PARAMETER ReturnRawBytes

            If this switch is set, the response body to the Duo request will be returned as raw bytes. By default the response is converted from its native JSON format into a PSObject.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'DELETE')] [string]$Method,
          [Parameter(Mandatory)] [string]$Uri,
          [hashtable]$AuthHeaders,
          [string]$CanonicalizedParameters,
          [switch]$ReturnRawBytes = $false,
          [string]$DuoEnv = $script:DuoDefaultEnv)

    # If any non-terminating errors occur in this function we should bail out.
    #$ErrorActionPreference = 'Stop'

    # Put the full HTTP header together.
    $headers = @{
        'Accept-Charset' = 'ISO-8859-1,utf-8'
        'Accept-Language' = 'en-US'
        'Accept-Encoding' = 'deflate,gzip'
        'Authorization' = $AuthHeaders['Authorization']
        'X-Duo-Date' = $AuthHeaders['X-Duo-Date']
    }

    If ($Uri -notlike 'https://*') {
        Throw "URI must begin with https. Uri = $Uri"
    }

    Try {

        # Create HTTP request and set its method.
        $request = [System.Net.HttpWebRequest]::CreateHttp($Uri)
        If ($request) { $request.Method = $Method }
        Else { Throw "Error creating HTTP request for URI: $Uri" }

        Write-Verbose ('[' + $request.Method + ' ' + $request.RequestUri + ']')

        # Set request encoding and user agent string.
        $request.Accept = 'application/json'
        $request.UserAgent = $script:DuoUserAgent

        # Set automatic decompression of the response to the request.
        $request.AutomaticDecompression = @([System.Net.DecompressionMethods]::Deflate, [System.Net.DecompressionMethods]::GZip)

        # Add all additional headers.
        Foreach($key In $headers.keys) { $request.Headers.Add($key, $headers[$key]) }

        # Check if a proxy server has been given and set it up if so.
        If ($script:DuoEnvironmentInfo[$DuoEnv].ProxyServer) {

            # Create the proxy object.
            $webProxy = New-Object System.Net.WebProxy
            If ($webProxy -eq $null) { Throw 'Error creating web proxy object' }

            # Set the proxy server and port. Make sure we are using HTTP as that is all the System.Net.WebRequest class supports.
            # HTTPS proxy addresses should not ever be needed. See below.
            # https://blogs.msdn.microsoft.com/jpsanders/2007/04/25/the-servicepointmanager-does-not-support-proxies-of-https-scheme-net-1-1-sp1/
            $proxyServer = $script:DuoEnvironmentInfo[$DuoEnv].ProxyServer
            If ($proxyServer -notmatch '^http') { $proxyServer = "http://$proxyServer" }
            Else { $proxyServer = $proxyServer -replace '^https://', 'http://' }
            If ($script:DuoEnvironmentInfo[$DuoEnv].ProxyPort) { $proxyServer += ':' + $script:DuoEnvironmentInfo[$DuoEnv].ProxyPort }
            $webProxy.Address = $proxyServer

            # Set the bypass list if available. Make sure each URI starts with a ';'.
            If ($script:DuoEnvironmentInfo[$DuoEnv].ProxyBypassList) {
                $bypassList = $script:DuoEnvironmentInfo[$DuoEnv].ProxyBypassList | ForEach-Object { If ($_ -match '^;') { $_ } Else { ';' + $_ } }
                Try { $webProxy.BypassList = $bypassList }
                Catch { Throw "Invalid proxy bypass list.`n$($_.Exception.Message)" }
            }

            # Set bypass on local setting if needed.
            If ($script:DuoEnvironmentInfo[$DuoEnv].ProxyBypassOnLocal) {
                $webProxy.BypassProxyOnLocal = $true
            }

            # Set credentials if needed.
            If ($script:DuoEnvironmentInfo[$DuoEnv].ProxyUseDefaultCredentials) {
                $webProxy.UseDefaultCredentials = $true
            } ElseIf ($script:DuoEnvironmentInfo[$DuoEnv].ProxyUsername) {
                If ($script:DuoEnvironmentInfo[$DuoEnv].ProxyPasswordEncrypted) {
                    $secPassword = $script:DuoEnvironmentInfo[$DuoEnv].ProxyPasswordEncrypted
                } ElseIf ($script:DuoEnvironmentInfo[$DuoEnv].ProxyPassword) {
                    $secPassword = ConvertTo-SecureString $script:DuoEnvironmentInfo[$DuoEnv].ProxyPassword -AsPlainText -Force
                }
                Try {
                    $creds = New-Object System.Management.Automation.PSCredential ($script:DuoEnvironmentInfo[$DuoEnv].ProxyUsername, $secPassword)
                    $webProxy.Credentials = $creds
                } Catch { Throw "Error setting proxy server credentials.`n$($_.Exception.Message)" }
            }

            Write-Debug "Send-DuoRequest : Proxy Setup : $($webProxy | Out-String)"

            # Add the proxy to the web request.
            Try { $request.Proxy = $webProxy }
            Catch { Throw "Error setting proxy server on web request: `n$($_.Exception.Message)" }

        }

        # If using POST or PUT then the request parameters also need to be put into the body of the request.
        If (($Method.ToUpper() -eq 'POST') -or ($Method.ToUpper() -eq 'PUT')) {

            # Get request parameter bytes for output stream and set content info.
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($CanonicalizedParameters)
            $request.ContentType = 'application/x-www-form-urlencoded'
            $request.ContentLength = $bytes.Length

            # Get output stream from request object and write out the request parameter bytes.
            [System.IO.Stream]$outputStream = [System.IO.Stream]$request.GetRequestStream()
            $outputStream.Write($bytes,0,$bytes.Length)
            $outputStream.Close()
            Remove-Variable -Name outputStream

        }

        Write-Verbose $request.Headers['Authorization']
        Write-Verbose $request.Headers['X-Duo-Date']

        # Send the request and wait for a response.
        [System.Net.HttpWebResponse]$response = $request.GetResponse()
        If ($response -eq $null) { Throw "Error retrieving response from URI: $Uri" }

        # Return just the raw bytes of the response body.
        If ($ReturnRawBytes) {

            # To get the bytes only we have to work directly with the response stream.
            $respStream = $response.GetResponseStream()

            # Need a buffer of known length to store bytes for each read operation.
            $buffer = New-Object System.Byte[] ($script:DuoBufferSize)

            $bytesRead = 0
            [byte[]]$respBodyBytes = @()
            While (($bytesRead = $respStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                $respBodyBytes += $buffer[0..($bytesRead - 1)]
            }

            # Return raw response body as bytes.
            Return $respBodyBytes

        # Convert the JSON response body to a PSObject if requested.
        } Else {

            # Get the response body.
            $respStreamReader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $respBody = $respStreamReader.ReadToEnd()
            $respStreamReader.Close()

            Try {
                $respBodyObj = ConvertFrom-Json -InputObject $respBody
            } Catch {
                Write-Warning "Response body could not be converted from JSON:`n$respBody"
                Write-Warning "JSON Conversion Exception: $($_.Exception.Message)"
            }

            # Return JSON converted response body.
            Return $respBodyObj

        }

    # Handle Web Request errors.
    } Catch [Net.WebException] {

        # Get the error from the response body if one exists and use it as a message in the error we are about to throw.
        If ($_.Exception.Response -ne $null) {
            [System.Net.HttpWebResponse]$response = $_.Exception.Response
            $respStreamReader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $respBody = $respStreamReader.ReadToEnd()
            $respStreamReader.Close()
            Throw $respBody
        } Else {
            Throw  # No response body so just rethrow the exception as is.
        }

    # Handle any other errors.
    } Catch {

        Throw  # Rethrow exception.

    # Clean up.
    } Finally {

        If ($response) {

            $response.Close()
            $response.Dispose()

        }

    }

}

#endregion Send-DuoRequest

#====================================================================================================================================================
################################
## Get-DuoAuthorizationHeader ##
################################

#region Get-DuoAuthorizationHeader

# This function is called by the public command Invoke-DuoRequest to build the headers and digitally sign them.
# It does this after Invoke-DuoRequest has already canonicalized the request parameters.

Function Get-DuoAuthorizationHeader {

    <#

        .SYNOPSIS

            Generates the Authroization header of the API call in a format required by the Duo API. This format includes the Duo integration key and a signed version of the API call's HTTP header. The returned string should be used as the value for the HTTP Authorization header.

        .DESCRIPTION

            Generates the Authroization header of the API call in a format required by the Duo API. This format includes the Duo integration key and a signed version of the API call's HTTP header. The returned string should be used as the value for the HTTP Authorization header.

            This header is generated based on the specified parameters.

            This function is intended for internal use by this module only.

        .PARAMETER Path

            The Duo API path for a given API call. This path should not include the API host but simply the path to the API resource.

            EX: '/auth/v2/auth'

        .PARAMETER Method

            The HTTP method by which to submit the Duo API call.

            EX: 'GET' or 'POST' or 'DELETE'

        .PARAMETER Date

            The current date and time specified in RFC2822 compliant format.

            EX: "Tue, 29 Nov 2016 18:27:20 -0000"

            To get the current data and time in this format run the Get-DuoRFC2822Date internal command or run the following from the command line:

                (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss -0000", ([System.Globalization.CultureInfo]::InvariantCulture))

        .PARAMETER CanonicalizedParameters

            A string representing all of the parameters being sent in the Duo API call which have been canonicalized as a standard URL-encoded string.

            NOTE: Duo does have some special handling of the URL-encoded parameters which is specified here: https://duo.com/docs/authapi#base-url
                  You can also use the Get-DuoCanonicalizeParameter internal module function to canonicalize the parameters according to Duo's restrictions.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([string]$Path,
          [string]$Method,
          [string]$Date,
          [string]$CanonicalizedParameters,
          [string]$DuoEnv = $script:DuoDefaultEnv)

    $canonicalizedRequest = Get-DuoCanonicalizeRequest -Path $Path -Method $Method -Date $Date -CanonicalizedParameters $CanonicalizedParameters -DuoEnv $DuoEnv
    $sig = Get-DuoHMACSignature -Data $canonicalizedRequest -DuoEnv $DuoEnv
    $authStr = $script:DuoEnvironmentInfo[$DuoEnv].IntegrationKey + ':' + $sig
    $basicAuthStr = Get-DuoEncode64 -PlainText $authStr

    Write-Debug "Get-DuoAuthorizationHeader : `nBasic $basicAuthStr"

    Return "Basic $basicAuthStr"

}

#endregion Get-DuoAuthorizationHeader

#====================================================================================================================================================
################################
## Get-DuoCanonicalizeRequest ##
################################

#region Get-DuoCanonicalizeRequest

# This function is called by the private command Get-DuoAuthorizationHeader to canonicalize the headers and request parameters into one multi-line string that will later be digitally signed.
# It does this after the public command Invoke-DuoRequest has already canonicalized the request parameters.

Function Get-DuoCanonicalizeRequest {

    <#

        .SYNOPSIS

            Generates the Authroization header of the API call prior to signing of the header.

        .DESCRIPTION

            Generates the Authroization header of the API call prior to signing of the header. This header is generated based on the specified parameters.

            This function is intended for internal use by this module only.

        .PARAMETER Path

            The Duo API path for a given API call. This path should not include the API host but simply the path to the API resource.

            EX: '/auth/v2/auth'

        .PARAMETER Method

            The HTTP method by which to submit the Duo API call.

            EX: 'GET' or 'POST' or 'DELETE'

        .PARAMETER Date

            The current date and time specified in RFC2822 compliant format.

            EX: "Tue, 29 Nov 2016 18:27:20 -0000"

            To get the current data and time in this format run the Get-DuoRFC2822Date internal command or run the following from the command line:

                (Get-Date).ToUniversalTime().ToString("ddd, dd MMM yyyy HH:mm:ss -0000", ([System.Globalization.CultureInfo]::InvariantCulture))

        .PARAMETER CanonicalizedParameters

            A string representing all of the parameters being sent in the Duo API call which have been canonicalized as a standard URL-encoded string.

            NOTE: Duo does have some special handling of the URL-encoded parameters which is specified here: https://duo.com/docs/authapi#base-url
                  You can also use the Get-DuoCanonicalizeParameter internal module function to canonicalize the parameters according to Duo's restrictions.

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([string]$Path,
          [string]$Method,
          [string]$Date,
          [string]$CanonicalizedParameters,
          [string]$DuoEnv = $script:DuoDefaultEnv)

    $apiHost = $script:DuoEnvironmentInfo[$DuoEnv].ApiHostname

    $lines = @($Date.Trim(), $Method.ToUpperInvariant().Trim(), $apiHost.ToLower().Trim(), $Path.Trim(), $CanonicalizedParameters.Trim())
    $canonicalizedRequest = $lines -join "`n"

    Write-Debug "Get-DuoCanonicalizeRequest : `n$canonicalizedRequest"

    Return $canonicalizedRequest

}

#endregion Get-DuoCanonicalizeRequest

#====================================================================================================================================================
##################################
## Get-DuoCanonicalizeParameter ##
##################################

#region Get-DuoCanonicalizeParameter

# This function is called by the public command Invoke-DuoRequest to canonicalize and URL encode the request parameters.

Function Get-DuoCanonicalizeParameter {

    <#

        .SYNOPSIS

            Canonicalizes a hashtable of parameters to be used in a Duo API call and returns it as a string.

        .DESCRIPTION

            Canonicalizes a hashtable of parameters to be used in a Duo API call and returns it as a string. Duo has special handling of the URL-encoded parameters which is specified here: https://duo.com/docs/authapi#base-url

            EX: username=janedoe&exFieldWithSpaces=some%20value%20with%20spaces

            This function is intended for internal use by this module only.

        .PARAMETER RequestParameters

            A hashtable which contains key/value pairs of each Duo API request parameter needed.

            EX: @{
                   username = 'janedoe'
                   exFieldWithSpaces = 'some value with spaces'
                 }

    #>

    [CmdletBinding()]

    Param([hashtable]$RequestParameters)

    If ($RequestParameters.Count -gt 0) {

        # We use an ArrayList instead of a standard array so we can easily sort it later.
        $paramLines = New-Object System.Collections.ArrayList

        Foreach ($key In $RequestParameters.keys) {

            # URL encode the the parameters.
            $param = [System.Web.HttpUtility]::UrlEncode($key) + '=' + [System.Web.HttpUtility]::UrlEncode($RequestParameters[$key])

            # Signatures require upper-case hex digits for URL encoded special characters.
            $param = [regex]::Replace($param, '(%[0-9A-Fa-f][0-9A-Fa-f])', { $args[0].Value.ToUpperInvariant() })

            # Just a few more special characters that need proper conversion/formatting.
            $param = [regex]::Replace($param, "([!'()*])", { '%' + [System.Convert]::ToByte($args[0].Value[0]).ToString('X') })
            $param = $param.Replace('%7E', '~')
            $param = $param.Replace('+', '%20')

            # Add the URL encoded parameter to the list of request parameters.
            $null = $paramLines.Add($param)

        }

        # Sort the parameters before putting them into one query string.
        $paramLines.Sort([System.StringComparer]::Ordinal)
        $canonicalizedParameters = $paramLines.ToArray() -join '&'

    } Else {
        $canonicalizedParameters = ''
    }

    Write-Debug "Get-DuoCanonicalizeParameter : `n$canonicalizedParameters"

    Return $canonicalizedParameters
}

#endregion Get-DuoCanonicalizeParameter

#====================================================================================================================================================
##########################
## Get-DuoHMACSignature ##
##########################

#region Get-DuoHMACSignature

Function Get-DuoHMACSignature {

    <#

        .SYNOPSIS

            Computes an HMAC SHA1 hash of the given data to be later used as the Authorization Header signature of the Duo API call.

        .DESCRIPTION

            Computes an HMAC SHA1 hash of the given data to be later used as the Authorization Header signature of the Duo API call. The key used to compute the hash is retrieved from the specified Duo environment configuration set. This function will attempt to use the SecretKeyEncrypted value first if it exist, otherwise it will look for the SecretKey value.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

            This function is intended for internal use by this module only.

        .PARAMETER Data

            The data that will be hashed. This is typically a canonicalized string representing specific parts of the HTTP header to be used in the Duo API call.

            See the following for details on the data format: https://duo.com/docs/authapi#authentication

        .PARAMETER DuoEnv

            A string matching a key in the Duo environment configuration hashtable to be used when making Duo API calls. If this parameter is not specified it will use the current default environment configuration.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

    #>

    [CmdletBinding()]

    Param([string]$Data,
          [string]$DuoEnv = $script:DuoDefaultEnv)

    Process {

        # Convert Duo secret key to bytes.
        If ($script:DuoEnvironmentInfo[$DuoEnv].SecretKeyEncrypted) {
            Try { $secretKeySecureStr = ConvertTo-SecureString -String $script:DuoEnvironmentInfo[$DuoEnv].SecretKeyEncrypted -ErrorAction Stop }
            Catch { Throw "Invalid Encrypted Secret Key : $($_.Exception.Message)" }
            [byte[]]$keyBytes = [System.Text.Encoding]::UTF8.GetBytes([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($secretKeySecureStr)))
        } Else {
            [byte[]]$keyBytes = [System.Text.Encoding]::UTF8.GetBytes($script:DuoEnvironmentInfo[$DuoEnv].SecretKey)
        }

        # Convert data to bytes.
        [byte[]]$dataBytes = [System.Text.Encoding]::UTF8.GetBytes($Data)

        # Create an HMAC SHA1 hash and add key.
        $hmacsha1 = New-Object System.Security.Cryptography.HMACSHA1
        $hmacsha1.Key = $keyBytes

        # Compute hash and convert it to a hex string.
        $null = $hmacsha1.ComputeHash($dataBytes)
        $hashHexStr = [System.BitConverter]::ToString($hmacsha1.Hash)

        # Remove dashes added by the BitConverter and make everyting lower case.
        $formattedHash = $hashHexStr.Replace('-', '').ToLower()

        Write-Debug "Get-DuoHMACSignature : `n$formattedHash"

        Return $formattedHash

    }
}

#endregion Get-DuoHMACSignature

#endregion Duo Helper Functions

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

#######################
## Utility Functions ##
#######################

#region Utility Functions

#====================================================================================================================================================
#####################
## Get-DuoEncode64 ##
#####################

#region Get-DuoEncode64

# Returns a Base64 encoded version of provided $Plaintext.
Function Get-DuoEncode64 {

    Param ($PlainText)

    [byte[]]$plainTextBytes = [System.Text.Encoding]::ASCII.GetBytes($PlainText)

    Return [System.Convert]::ToBase64String($plainTextBytes)

}

#endregion Get-DuoEncode64

#====================================================================================================================================================
########################
## Get-DuoRFC2822Date ##
########################

#region Get-DuoRFC2822Date

# Returns an RFC2822 compliant date/time string.
Function Get-DuoRFC2822Date {

    $date = Get-Date
    $dateString = $date.ToUniversalTime().ToString('ddd, dd MMM yyyy HH:mm:ss -0000', ([System.Globalization.CultureInfo]::InvariantCulture))

    Return $dateString

}

#region Get-DuoRFC2822Date

#====================================================================================================================================================
########################
## Get-DuoSystemProxy ##
########################

#region Get-DuoSystemProxy

# Returns an object with the system proxy settings.
Function Get-DuoSystemProxy {

    [CmdletBinding()]

    Param()

    Begin {

        # Result proxy settings object.
        $ProxySettings = New-Object PSCustomObject -Property @{
            ProxyEnabled = $false
            ProxyServer = ''
            BypassList = ''
        }

    }

    Process {

        # Retrieve the binary proxy setting data.
        $regVal = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections" -Name WinHttpSettings -ErrorAction SilentlyContinue).WinHttPSettings
        If ($regVal -eq $null) { Return }

        # The first part of this binary data appears to be some static information followed by an Int32 that is either 1 for proxy cleared or 3 for proxy set.
        $headerLength = 12 - 1  # 8 bytes static info + 4 bytes Int32 = 12 bytes (starting at zero so minus one).

        # Our field lengths are 4 byte Int32 objects.
        $Int32ByteStop = 4 - 1  # Starting at zero.

        # Get proxy server string length.
        $proxyLengthByteStart = $headerLength + 1
        $proxyLengthByteStop = $proxyLengthByteStart + $Int32ByteStop
        $proxyLength = [System.BitConverter]::ToInt32($regVal[$proxyLengthByteStart..$proxyLengthByteStop], 0)

        If ($proxyLength -gt 0) {

            # Get the proxy servername string.
            $proxyByteStart = $proxyLengthByteStop + 1
            $proxyByteStop = $proxyByteStart + ($proxyLength - 1)
            $proxy = -join ($regVal[$proxyByteStart..$proxyByteStop] | ForEach-Object { [char]$_ })

            # Get the bypass list string length.
            $bypassLengthByteStart = $proxyByteStop + 1
            $bypassLengthByteStop = $bypassLengthByteStart + $Int32ByteStop
            $bypassLength = [System.BitConverter]::ToInt32($regVal[$bypassLengthByteStart..$bypassLengthByteStop], 0)

            If ($bypassLength -gt 0) {

                # Get the bypass list string.
                $bypassByteStart = $bypassLengthByteStop + 1
                $bypassByteStop = $bypassByteStart + ($bypassLength - 1)
                $bypassList = -join ($regVal[$bypassByteStart..$bypassByteStop] | ForEach-Object { [char]$_ })

            } Else {
                $bypasslist = ''
            }

            $ProxySettings.ProxyEnabled = $true
            $ProxySettings.ProxyServer = $proxy
            $ProxySettings.BypassList = $bypassList

        }
    }

    End {

        Return $ProxySettings
    }

}

#region Get-DuoSystemProxy

#====================================================================================================================================================
#################
## Test-DuoEnv ##
#################

#region Test-DuoEnv

# Test to ensure the provided Duo environment exists within the current Duo evironment configuration hashtable.
Function Test-DuoEnv {

    Param ([Parameter(Mandatory)] [string]$DuoEnv)

    If ($script:DuoEnvironmentInfo[$DuoEnv]) { Return $true }
    Else { Throw ("The $DuoEnv key is not found in the DuoEnvironmentInfo hashtable. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`nKeys:$($script:DuoEnvironmentInfo.Keys)") }

}

#endregion Test-DuoEnv

#====================================================================================================================================================
###########################
## Test-DuoEnvInfoFormat ##
###########################

#region Test-DuoEnvInfoFormat

Function Test-DuoEnvInfoFormat {

    <#

        .SYNOPSIS

            Verifies the provided Duo environment configuration hashtable is correctly formatted.

        .DESCRIPTION

            Verifies the provided Duo environment configuration hashtable is correctly formatted. This configuration hashtable can created in a number of ways.

            For details on environment configurations please see https://github.com/The-New-Guy/Posh-DuoAPI.

        .NOTES

            The $script:DuoEnvironmentInfo hashtable must be of the following format to properly configure the Duo environment info. Additionally the current $script:DefaultDuoEnv must match at least one of the provided keys in the main hashtable.

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

    #>

    [CmdletBinding()]

    Param()

    Write-Debug "Environment Count : $($script:DuoEnvironmentInfo.Count)"
    Write-Debug "Environment Keys : `n$($script:DuoEnvironmentInfo.Keys | Out-String)"
    Write-Debug "Environment Settings : `n$(($script:DuoEnvironmentInfo.Keys | ForEach-Object { "$_ = @{`n" + ($script:DuoEnvironmentInfo[$_] | Out-String) + "}`n" }) -join "`n")"

    # Verify the whole thing is a non-empty hashtable.
    If (($script:DuoEnvironmentInfo -ne $null) -and ($script:DuoEnvironmentInfo -is [hashtable]) -and ($script:DuoEnvironmentInfo.Count -gt 0)) {

        # Verify that the Default Duo Env is contianed within this hashtable.
        If (-not $script:DuoEnvironmentInfo.Contains($script:DuoDefaultEnv)) {
            Throw "The DefaultDuoEnv could not be found as a key to the DuoEnvironmentInfo hashtable:`nDefaultDuoEnv = $($script:DuoDefaultEnv)`nDuoEnvironmentIfno = $($script:DuoEnvironmentInfo | Out-String)"
        }

        # Verify each key is associated with another hashtable with the proper format.
        Foreach ($env In $script:DuoEnvironmentInfo.Keys) {

            ## Check required keys. ##

            # Verify the inner hashtables are in fact hashtables.
            If (($script:DuoEnvironmentInfo[$env] -eq $null) -or ($script:DuoEnvironmentInfo[$env] -isnot [hashtable])) {
                Throw "The $env key in the DuoEnvironmentInfo hashtable is not in the proper format. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
            }

            # The 'IntegrationKey' should contain the DUO API Integration Key.
            If (($script:DuoEnvironmentInfo[$env].IntegrationKey -eq $null) -or
                ($script:DuoEnvironmentInfo[$env].IntegrationKey -isnot [string]) -or
                ($script:DuoEnvironmentInfo[$env].IntegrationKey.Length -eq 0)) {
                Throw "The $env key in the DuoEnvironmentInfo hashtable is missing the IntegrationKey key or it is in the wrong format. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
            }

            # The 'ApiHostname' should contain the DUO API Hostname that will be servicing the API calls.
            If (($script:DuoEnvironmentInfo[$env].ApiHostname -eq $null) -or
                ($script:DuoEnvironmentInfo[$env].ApiHostname -isnot [string]) -or
                ($script:DuoEnvironmentInfo[$env].ApiHostname.Length -eq 0)) {
                Throw "The $env key in the DuoEnvironmentInfo hashtable is missing the ApiHostname key or it is in the wrong format. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
            }

            # The final required key must be one of the following, but not both.
            # 1. The 'SecretKey' should contain the DUO API Application Secret Key in plain text.
            # 2. The 'SecretKeyEncrypted' should contain the DUO API Application Secret Key as a string representation of a SecureString.
            If ((($script:DuoEnvironmentInfo[$env].SecretKey -eq $null) -or
                 ($script:DuoEnvironmentInfo[$env].SecretKey -isnot [string]) -or
                 ($script:DuoEnvironmentInfo[$env].SecretKey.Length -eq 0)) -and
                (($script:DuoEnvironmentInfo[$env].SecretKeyEncrypted -eq $null) -or
                 ($script:DuoEnvironmentInfo[$env].SecretKeyEncrypted -isnot [string]) -or
                 ($script:DuoEnvironmentInfo[$env].SecretKeyEncrypted.Length -eq 0))) {
                Throw "The $env key in the DuoEnvironmentInfo hashtable is missing the SecretKey/SecretKeyEncrypted key or it is in the wrong format. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
            }

            ## Check optional proxy keys. ##

            # Only bother check if the ProxyServer key exists to begin with.
            If ($script:DuoEnvironmentInfo[$env].ProxyServer -ne $null) {

                # The 'ProxyServer' should contain the hostname of the proxy server to use.
                If (($script:DuoEnvironmentInfo[$env].ProxyServer -isnot [string]) -or ($script:DuoEnvironmentInfo[$env].ProxyServer.Length -eq 0)) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an improperly formatted ProxyServer key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }

                # Each of the additional proxy keys below should either not exist OR match the requirements below.

                # The 'ProxyPort' should contain the port use to connect to the proxy server.
                If (($script:DuoEnvironmentInfo[$env].ProxyPort -ne $null) -and
                    ((($script:DuoEnvironmentInfo[$env].ProxyPort -isnot [int]) -and ($script:DuoEnvironmentInfo[$env].ProxyPort -isnot [string])) -or
                     (($script:DuoEnvironmentInfo[$env].ProxyPort -as [int]) -le 0))) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an improperly formatted ProxyPort key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }

                # The 'ProxyBypassList' should contain an array of URIs that will not use the proxy server.
                If (($script:DuoEnvironmentInfo[$env].ProxyBypassList -ne $null) -and ($script:DuoEnvironmentInfo[$env].ProxyBypassList -isnot [array])) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an improperly formatted ProxyBypassList key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }

                # The 'ProxyBypassOnLocal' switch should be a bool or a switch.
                If (($script:DuoEnvironmentInfo[$env].ProxyBypassOnLocal -ne $null) -and ($script:DuoEnvironmentInfo[$env].ProxyBypassOnLocal -isnot [bool])) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an improperly formatted ProxyBypassOnLocal key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }

                # The 'ProxyUsername' should contain the username of the account needed to authenticate to the proxy server.
                If (($script:DuoEnvironmentInfo[$env].ProxyUsername -ne $null) -and
                    (($script:DuoEnvironmentInfo[$env].ProxyUsername -isnot [string]) -or ($script:DuoEnvironmentInfo[$env].ProxyUsername.Length -eq 0))) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an improperly formatted ProxyUsername key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }

                # The 'ProxyUseDefaultCredentials' switch should be a bool or a switch.
                If (($script:DuoEnvironmentInfo[$env].ProxyUseDefaultCredentials -ne $null) -and ($script:DuoEnvironmentInfo[$env].ProxyUseDefaultCredentials -isnot [bool])) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an improperly formatted ProxyUseDefaultCredentials key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }

                # The proxy password keys must be one of the following.
                # 1. The 'ProxyPassword' should contain the proxy password in plain text.
                # 2. The 'ProxyPasswordEncrypted' should contain the proxy password as a string representation of a SecureString.
                # 3. Neither should exist is the 'ProxyUsername' key does not exist and if it does exist then one and only one ProxyPassword/ProxyPasswordEncrypted should exist.
                If (($script:DuoEnvironmentInfo[$env].ProxyUsername -ne $null) -and ($script:DuoEnvironmentInfo[$env].ProxyPassword -eq $null) -and ($script:DuoEnvironmentInfo[$env].ProxyPasswordEncrypted -eq $null)) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an ProxyUsername key but does not contain a ProxyPassword or ProxyPasswordEncrypted key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }

                If (($script:DuoEnvironmentInfo[$env].ProxyUsername -ne $null) -and
                    ((($script:DuoEnvironmentInfo[$env].ProxyPassword -eq $null) -or
                      ($script:DuoEnvironmentInfo[$env].ProxyPassword -isnot [string]) -or
                      ($script:DuoEnvironmentInfo[$env].ProxyPassword.Length -eq 0)) -and
                     (($script:DuoEnvironmentInfo[$env].ProxyPasswordEncrypted -eq $null) -or
                      ($script:DuoEnvironmentInfo[$env].ProxyPasswordEncrypted -isnot [string]) -or
                      ($script:DuoEnvironmentInfo[$env].ProxyPasswordEncrypted.Length -eq 0)))) {
                    Throw "The $env key in the DuoEnvironmentInfo hashtable contains an improperly formatted ProxyPassword or ProxyPasswordEncrypted key. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo[$env] | Out-String)"
                }
            }
        }
    } Else {
        Throw "The DuoEnvironmentInfo hashtable is not defined or is not in the proper format. See https://github.com/The-New-Guy/Posh-DuoAPI for details:`n$($script:DuoEnvironmentInfo | Out-String)"
    }

    # If we made it this far then I call that a success.
    Return $true

}

#endregion Test-DuoEnvInfoFormat

#endregion Utility Functions

#>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>