Function Get-CiFileHashes {
    [CmdletBinding()]
    [OutputType([WDACConfig.CodeIntegrityHashes])]
    param (
        [ArgumentCompleter([WDACConfig.ArgCompleter.AnyFilePathsPicker])]
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$FilePath,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    if (!$SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }
    return [WDACConfig.CiFileHash]::GetCiFileHashes($FilePath)
    <#
.SYNOPSIS
    Calculates the Authenticode hash and first page hash of the PEs with SHA1 and SHA256 algorithms.
    The hashes are compliant with the App Control for Business policy.
    For more information please visit: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#more-information-about-hashes
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CiFileHashes
.PARAMETER Path
    The path to the file for which the hashes are to be calculated.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.INPUTS
    System.IO.FileInfo
.OUTPUTS
    [WDACConfig.CodeIntegrityHashes]

    The output has the following properties
    - SHA1Page: The SHA1 hash of the first page of the PE file.
    - SHA256Page: The SHA256 hash of the first page of the PE file.
    - SHA1Authenticode: The SHA1 hash of the Authenticode signature of the PE file.
    - SHA256Authenticode: The SHA256 hash of the Authenticode signature of the PE file.
.NOTES
    If the is non-conformant, the function will calculate the flat hash of the file using the specified hash algorithm
    And return them as the Authenticode hashes. This is compliant with how the WDAC engine in Windows works.
#>
}
