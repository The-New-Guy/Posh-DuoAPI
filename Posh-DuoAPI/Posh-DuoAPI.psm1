#Requires -Version 3.0

# This is the module script file that will be executed first upon importing this module. For simplicity this file should reamin
# fairly minimalistic and should mostly just dot source other files to bring in definitions for this module.

#==================================================================================================================================

#####################
# Module Parameters #
#####################

# The Duo environment info can be passed to the module during the Import-Modue command using the -ArguementList parameter.
Param([hashtable]$DuoEnvironmentInfo = @{},
      [string]$DuoDefaultEnv)

# Hashtables pass by reference. So we have to recreate/clone them to prevent the user from modifying the hashtable they passed in
# and in turn modifying the hashtable stored in this module without a proper validation test being performed on it.
# If the user did not provide any environment info during the Import-Module command then the DuoEnvironmentInfo.ps1 file will be 
# used. If the user provided environment info but did not provide a default Duo environment then throw an error.
$userEnvironmentInfo = @{}
$DuoEnvironmentInfo.Keys | ForEach-Object { $userEnvironmentInfo[$_] = $DuoEnvironmentInfo[$_].Clone() }
$script:DuoEnvironmentInfo = $userEnvironmentInfo
$script:DuoDefaultEnv = If (($DuoEnvironmentInfo.Count -gt 1) -and ($DuoDefaultEnv.Length -eq 0)) { Throw 'Must provide a default Duo environment key with argument list.' } Else { $DuoDefaultEnv }

#==================================================================================================================================

#########################
# Module Initialization #
#########################

# Load the Duo environment info such as integration key, secret key and api host.
# Either use the info provided by the user on import of the module via the -ArguementList parameter or load from a file.
# The file will define the $DuoEnvironmentInfo variable in the script scope (a.k.a. module scope in this case).

If ($script:DuoEnvironmentInfo.Count -eq 0) {
    . "$PSScriptRoot\DuoEnvironmentInfo\DuoEnvironmentInfo.ps1"
}

# Using the System.Web.HttpUtility .Net library.
[System.Reflection.Assembly]::Load('System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a') | Out-Null

# LoadWithPartialName is deprecated...but so less problematic for simple applications like this.
# However, it is still useful in determining what string to use above.
# ([System.Reflection.Assembly]::LoadWithPartialName('System.Web')).FullName

#==================================================================================================================================

######################
# Add Custom Content #
######################

# ~~~ Variables ~~~ #

. "$PSScriptRoot\Variables\ModuleVariables.ps1"

# ~~~ Functions ~~~ #

. "$PSScriptRoot\Functions\Private.ps1"
. "$PSScriptRoot\Functions\Public.ps1"

#==================================================================================================================================

#######################
# Module Finalization #
#######################

# Verify the Duo environment info is in proper format.

Test-DuoEnvInfoFormat
