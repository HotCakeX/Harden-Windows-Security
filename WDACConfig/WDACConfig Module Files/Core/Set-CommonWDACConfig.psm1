Function Set-CommonWDACConfig {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    Param(
        [ArgumentCompleter({
                foreach ($Item in [WDACConfig.CertCNz]::new().GetValidValues()) {
                    if ($Item.Contains(' ')) {
                        "'$Item'"
                    }
                }
            })]
        [parameter(Mandatory = $false)][System.String]$CertCN,

        [ArgumentCompleter([WDACConfig.ArgCompleter.SingleCerFilePicker])]
        [ValidateScript({ ([System.IO.File]::Exists($_)) -and ($_.extension -eq '.cer') }, ErrorMessage = 'The path you selected is not a file path for a .cer file.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$CertPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.ExeFilePathsPicker])]
        [ValidateScript({ ([System.IO.File]::Exists($_ )) -and ($_.extension -eq '.exe') }, ErrorMessage = 'The path you selected is not a file path for a .exe file.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignToolPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [ValidateScript({
                try {
                    $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                }
                catch {
                    throw 'The selected file is not a valid WDAC XML policy.'
                }

                # If no indicators of a signed policy are found, proceed to the next validation
                if (!$RedFlag1 -and !$RedFlag2) {

                    # Ensure the selected base policy xml file is valid
                    if ( [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) ) {
                        return $True
                    }
                }
                else {
                    throw 'The selected policy xml file is Signed, Please select an Unsigned policy.'
                }
            }, ErrorMessage = 'The selected policy xml file is Signed, Please select an Unsigned policy.')]
        [parameter(Mandatory = $false)][System.IO.FileInfo]$UnsignedPolicyPath,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [ValidateScript({
                try {
                    $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                }
                catch {
                    throw 'The selected file is not a valid WDAC XML policy.'
                }

                # If indicators of a signed policy are found, proceed to the next validation
                if ($RedFlag1 -or $RedFlag2) {

                    # Ensure the selected base policy xml file is valid
                    if ( [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) ) {
                        return $True
                    }
                }
                else {
                    throw 'The selected policy xml file is Unsigned, Please select a Signed policy.'
                }
            }, ErrorMessage = 'The selected policy xml file is Unsigned, Please select a Signed policy.')]
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
.COMPONENT
    Windows Defender Application Control, WDACConfig module
.FUNCTIONALITY
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
