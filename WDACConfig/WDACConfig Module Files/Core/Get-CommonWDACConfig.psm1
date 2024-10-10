Function Get-CommonWDACConfig {
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    [WDACConfig.UserConfiguration]::Get()
    <#
.SYNOPSIS
    Query and Read common values for parameters used by WDACConfig module
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CommonWDACConfig
.DESCRIPTION
    Reads and gets the values from the User Config JSON file.
#>
}
