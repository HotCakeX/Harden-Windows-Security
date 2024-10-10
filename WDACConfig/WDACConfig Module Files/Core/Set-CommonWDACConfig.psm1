Function Set-CommonWDACConfig {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param(
        [parameter(Mandatory = $false)][System.String]$CertCN,

        [ArgumentCompleter([WDACConfig.ArgCompleter.SingleCerFilePicker])]
        [ValidateScript({ ([System.IO.File]::Exists($_)) -and ($_.extension -eq '.cer') }, ErrorMessage = 'The path you selected is not a file path for a .cer file.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$CertPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.ExeFilePathsPicker])]
        [ValidateScript({ ([System.IO.File]::Exists($_ )) -and ($_.extension -eq '.exe') }, ErrorMessage = 'The path you selected is not a file path for a .exe file.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignToolPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$UnsignedPolicyPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignedPolicyPath
    )
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    [WDACConfig.UserConfiguration]::Set($SignedPolicyPath, $UnsignedPolicyPath, $SignToolPath, $CertCN, $CertPath, $null, $null, $null, $null)
    <#
.SYNOPSIS
    Add/Change common values for parameters used by WDACConfig module
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig
.DESCRIPTION
    Add/Change common values for parameters used by WDACConfig module so that you won't have to provide values for those repetitive parameters each time you need to use the WDACConfig module cmdlets.
.PARAMETER SignedPolicyPath
    Path to a Signed WDAC xml policy
.PARAMETER UnsignedPolicyPath
    Path to an Unsigned WDAC xml policy
.PARAMETER CertCN
    Certificate common name
.PARAMETER SignToolPath
    Path to the SignTool.exe
.PARAMETER CertPath
    Path to a .cer certificate file
.INPUTS
    System.IO.FileInfo
    System.String
.OUTPUTS
    System.Object[]
.EXAMPLE
    Set-CommonWDACConfig -CertCN "wdac certificate"
.EXAMPLE
    Set-CommonWDACConfig -CertPath "C:\Users\Admin\WDACCert.cer"
.EXAMPLE
    Set-CommonWDACConfig -SignToolPath 'D:\Programs\signtool.exe' -CertCN 'wdac certificate' -CertPath 'C:\Users\Admin\WDACCert.cer'
#>
}
