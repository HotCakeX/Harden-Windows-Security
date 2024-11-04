Function Remove-CommonWDACConfig {
    [CmdletBinding(
        PositionalBinding = $false
    )]
    Param(
        [parameter(Mandatory = $false)][switch]$CertCN,
        [parameter(Mandatory = $false)][switch]$CertPath,
        [parameter(Mandatory = $false)][switch]$SignToolPath,
        [parameter(Mandatory = $false)][switch]$UnsignedPolicyPath,
        [parameter(Mandatory = $false)][switch]$SignedPolicyPath,
        [parameter(Mandatory = $false)][switch]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false)][switch]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false)][switch]$StrictKernelModePolicyTimeOfDeployment,
        [parameter(Mandatory = $false)][switch]$AutoUpdate
    )
    [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
    [WDACConfig.UserConfiguration]::Remove($SignedPolicyPath, $UnsignedPolicyPath, $SignToolPath, $CertCN, $CertPath, $StrictKernelPolicyGUID, $StrictKernelNoFlightRootsPolicyGUID, $LastUpdateCheck, $StrictKernelModePolicyTimeOfDeployment, $AutoUpdate)
    <#
.SYNOPSIS
    Removes common values for parameters used by WDACConfig module from the User Configurations JSON file. If you don't use it with any parameters, then all User Configs will be deleted.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-CommonWDACConfig
.PARAMETER SignedPolicyPath
    Removes the SignedPolicyPath from User Configs
.PARAMETER UnsignedPolicyPath
    Removes the UnsignedPolicyPath from User Configs
.PARAMETER CertCN
    Removes the CertCN from User Configs
.PARAMETER SignToolPath
    Removes the SignToolPath from User Configs
.PARAMETER CertPath
    Removes the CertPath from User Configs
.PARAMETER StrictKernelPolicyGUID
    Removes the StrictKernelPolicyGUID from User Configs
.PARAMETER StrictKernelNoFlightRootsPolicyGUID
    Removes the StrictKernelNoFlightRootsPolicyGUID from User Configs
.PARAMETER StrictKernelModePolicyTimeOfDeployment
    Removes the StrictKernelModePolicyTimeOfDeployment from User Configs
.PARAMETER AutoUpdate
    Removes the AutoUpdate from User Configs
.INPUTS
    System.Management.Automation.SwitchParameter
.EXAMPLE
    Remove-CoreWDACConfig -CertCN 
.EXAMPLE
    Remove-CoreWDACConfig -CertPath
#>
}