Function Confirm-WDACConfig {
    [CmdletBinding(DefaultParameterSetName = 'List Active Policies')]
    [OutputType([System.String], [System.Object])]
    Param(
        [Alias('L')]
        [Parameter(Mandatory = $false, ParameterSetName = 'List Active Policies')][System.Management.Automation.SwitchParameter]$ListActivePolicies,
        [Alias('V')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Verify WDAC Status')][System.Management.Automation.SwitchParameter]$VerifyWDACStatus,
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Check SmartAppControl Status')][System.Management.Automation.SwitchParameter]$CheckSmartAppControlStatus
    )
    DynamicParam {
        # Add the dynamic parameters to the param dictionary
        $ParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

        if ($PSBoundParameters['ListActivePolicies']) {

            # Create a dynamic parameter for -OnlyBasePolicies
            $OnlyBasePoliciesDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'List Active Policies'
                HelpMessage      = 'Only List Base Policies'
            }
            $ParamDictionary.Add('OnlyBasePolicies', [System.Management.Automation.RuntimeDefinedParameter]::new(
                    'OnlyBasePolicies',
                    [System.Management.Automation.SwitchParameter],
                    [System.Management.Automation.ParameterAttribute[]]@($OnlyBasePoliciesDynamicParameter)
                ))

            # Create a dynamic parameter for -OnlySupplementalPolicies
            $OnlySupplementalPoliciesDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'List Active Policies'
                HelpMessage      = 'Only List Supplemental Policies'
            }
            $ParamDictionary.Add('OnlySupplementalPolicies', [System.Management.Automation.RuntimeDefinedParameter]::new(
                    'OnlySupplementalPolicies',
                    [System.Management.Automation.SwitchParameter],
                    [System.Management.Automation.ParameterAttribute[]]@($OnlySupplementalPoliciesDynamicParameter)
                ))

            # Create a dynamic parameter for -OnlySystemPolicies
            $OnlySystemPoliciesDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'List Active Policies'
                HelpMessage      = 'Only List System Policies'
            }
            $ParamDictionary.Add('OnlySystemPolicies', [System.Management.Automation.RuntimeDefinedParameter]::new(
                    'OnlySystemPolicies',
                    [System.Management.Automation.SwitchParameter],
                    [System.Management.Automation.ParameterAttribute[]]@($OnlySystemPoliciesDynamicParameter)
                ))
        }

        # Create a dynamic parameter for -SkipVersionCheck, Adding this parameter as dynamic will make it appear at the end of the parameters
        $SkipVersionCheckDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
            Mandatory        = $false
            # To make this parameter available for all parameter sets
            ParameterSetName = '__AllParameterSets'
            HelpMessage      = 'Skip Version Check'
        }
        $ParamDictionary.Add('SkipVersionCheck', [System.Management.Automation.RuntimeDefinedParameter]::new(
                'SkipVersionCheck',
                [System.Management.Automation.SwitchParameter],
                [System.Management.Automation.ParameterAttribute[]]@($SkipVersionCheckDynamicParameter)
            ))

        return $ParamDictionary
    }
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        # Regular parameters are automatically bound to variables in the function scope
        # Dynamic parameters however, are only available in the parameter dictionary, which is why we have to access them using $PSBoundParameters
        # or assign them manually to another variable in the function's scope
        [System.Management.Automation.SwitchParameter]$OnlyBasePolicies = $($PSBoundParameters['OnlyBasePolicies'])
        [System.Management.Automation.SwitchParameter]$OnlySupplementalPolicies = $($PSBoundParameters['OnlySupplementalPolicies'])
        [System.Management.Automation.SwitchParameter]$OnlySystemPolicies = $($PSBoundParameters['OnlySystemPolicies'])
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck = $($PSBoundParameters['SkipVersionCheck'])

        if (-NOT $SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }

        # If no main parameter was passed, run all of them
        if (!$ListActivePolicies -and !$VerifyWDACStatus -and !$CheckSmartAppControlStatus) {

            [System.Collections.Generic.List[WDACConfig.CiPolicyInfo]]$PoliciesDeployedResults = [WDACConfig.CiToolHelper]::GetPolicies($false, $true, $true)
            Write-ColorfulTextWDACConfig -Color Lavender -InputText "$($PoliciesDeployedResults.count) policies are deployed"
            $PoliciesDeployedResults

            $VerifyWDACStatus = $true
            $CheckSmartAppControlStatus = $true
        }
    }

    process {
        if ($ListActivePolicies) {
            if ($OnlyBasePolicies) {
                [System.Collections.Generic.List[WDACConfig.CiPolicyInfo]]$OnlyBasePoliciesResults = [WDACConfig.CiToolHelper]::GetPolicies($false, $true, $false)
                Write-ColorfulTextWDACConfig -Color Lavender -InputText "$($OnlyBasePoliciesResults.count) base policies are deployed"
                $OnlyBasePoliciesResults
            }
            elseif ($OnlySupplementalPolicies) {
                [System.Collections.Generic.List[WDACConfig.CiPolicyInfo]]$OnlySupplementalPoliciesResults = [WDACConfig.CiToolHelper]::GetPolicies($false, $false, $true)
                Write-ColorfulTextWDACConfig -Color Lavender -InputText "$($OnlySupplementalPoliciesResults.count) Supplemental policies are deployed"
                $OnlySupplementalPoliciesResults
            }
            elseif ($OnlySystemPolicies) {
                [System.Collections.Generic.List[WDACConfig.CiPolicyInfo]]$OnlySystemPoliciesResults = [WDACConfig.CiToolHelper]::GetPolicies($true, $false, $false)
                Write-ColorfulTextWDACConfig -Color Lavender -InputText "$($OnlySystemPoliciesResults.count) System policies are deployed"
                $OnlySystemPoliciesResults
            }
            else {
                [System.Collections.Generic.List[WDACConfig.CiPolicyInfo]]$PoliciesDeployedResults = [WDACConfig.CiToolHelper]::GetPolicies($false, $true, $true)
                Write-ColorfulTextWDACConfig -Color Lavender -InputText "$($PoliciesDeployedResults.count) policies are deployed"
                $PoliciesDeployedResults
            }
        }

        if ($VerifyWDACStatus) {
            [WDACConfig.Logger]::Write('Checking the status of WDAC using Get-CimInstance')
            [WDACConfig.DeviceGuardInfo]::GetDeviceGuardStatus()
            Write-ColorfulTextWDACConfig -Color Lavender -InputText "2 -> Enforced`n1 -> Audit mode`n0 -> Disabled/Not running`n"
        }

        if ($CheckSmartAppControlStatus) {
            [WDACConfig.Logger]::Write('Checking the status of Smart App Control using Get-MpComputerStatus')
            Get-MpComputerStatus | Select-Object -Property SmartAppControlExpiration, SmartAppControlState
            if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
                Write-ColorfulTextWDACConfig -Color Pink -InputText "`nSmart App Control is in Evaluation mode."
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'On') {
                Write-ColorfulTextWDACConfig -Color Pink -InputText "`nSmart App Control is turned on."
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'Off') {
                Write-ColorfulTextWDACConfig -Color Pink -InputText "`nSmart App Control is turned off."
            }
        }
    }

    <#
.SYNOPSIS
    Shows the status of WDAC on the system, lists the currently deployed policies and shows the details about each of them.
    It can also show the status of Smart App Control.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig
.DESCRIPTION
    Using official Microsoft methods, Show the status of App Control for Business on the system, list the current deployed policies and show details about each of them.
.PARAMETER ListActivePolicies
    Lists the currently deployed policies and shows details about each of them
.PARAMETER OnlySystemPolicies
    Shows only the system policies
.PARAMETER OnlyBasePolicies
    Shows only the Base policies
.PARAMETER OnlySupplementalPolicies
    Shows only the Supplemental policies
.PARAMETER VerifyWDACStatus
    Shows the status of App Control for Business on the system
.PARAMETER CheckSmartAppControlStatus
    Checks the status of Smart App Control and reports the results on the console
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.EXAMPLE
    Confirm-WDACConfig -ListActivePolicies -OnlyBasePolicies
.EXAMPLE
    Confirm-WDACConfig -ListActivePolicies -OnlySupplementalPolicies
.EXAMPLE
    Confirm-WDACConfig -ListActivePolicies
.INPUTS
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
    System.Object
#>
}
