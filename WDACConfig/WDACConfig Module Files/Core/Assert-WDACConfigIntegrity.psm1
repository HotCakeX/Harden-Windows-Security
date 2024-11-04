Function Assert-WDACConfigIntegrity {
    [CmdletBinding()]
    param (
        [Alias('S')][Parameter(Mandatory = $false)][switch]$SaveLocally,
        [Alias('P')][Parameter(Mandatory = $false)][System.IO.DirectoryInfo]$Path = "$([WDACConfig.GlobalVars]::ModuleRootPath)\..\Utilities\"
    )
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement
    return [WDACConfig.AssertWDACConfigIntegrity]::Invoke($SaveLocally, $Path)
    <#
.SYNOPSIS
    Gets the SHA2-512 hashes of files in the WDACConfig and compares them with the ones in the cloud and shows the differences.
.DESCRIPTION
    The Assert-WDACConfigIntegrity function scans all the relevant files in the WDACConfig's folder and its subfolders, calculates their SHA2-512 hashes in hexadecimal format,
    Then it downloads the cloud CSV file from the GitHub repository and compares the hashes of the local files with the ones in the cloud.
    By doing so, you can ascertain that the files in your local WDACConfig folder are identical to the ones in the cloud and devoid of any interference.
    If there is any indication of tampering, the outcomes will be displayed on the console.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Assert-WDACConfigIntegrity
.PARAMETER SaveLocally
    Indicates that the function should save the results to a CSV file locally.
    You don't need to use this parameter.
.PARAMETER Path
    Specifies the path to save the CSV file to. The default path is the Utilities folder in the WDACConfig's folder.
    This is used before uploading to GitHub to renew the hashes.
    You don't need to use this parameter.
.INPUTS
    System.Management.Automation.SwitchParameter
    System.IO.DirectoryInfo
.OUTPUTS
    System.String
    System.Object[]
.EXAMPLE
    Assert-WDACConfigIntegrity
#>
}