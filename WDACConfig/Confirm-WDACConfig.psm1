#Requires -RunAsAdministrator
function Confirm-WDACConfig {
    [CmdletBinding(DefaultParameterSetName = 'List Active Policies')]
    Param(
        [Alias('L')]
        [Parameter(Mandatory = $false, ParameterSetName = 'List Active Policies')][Switch]$ListActivePolicies,
        [Alias('V')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Verify WDAC Status')][Switch]$VerifyWDACStatus,
        [Alias('S')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Check SmartAppControl Status')][Switch]$CheckSmartAppControlStatus,
               
        [Parameter(Mandatory = $false, DontShow = $true)][Switch]$DummyParameter, # To hide common parameters
        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck
    )
    
    DynamicParam {
        if ($PSBoundParameters['ListActivePolicies']) {
           
            # Add the dynamic parameters to the param dictionary
            $ParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
           
            # Create a dynamic parameter for -OnlyBasePolicies
            $OnlyBasePoliciesDynamicParameter = [System.Management.Automation.ParameterAttribute]@{
                Mandatory        = $false
                ParameterSetName = 'List Active Policies'
                HelpMessage      = 'Only List Base Policies'
            }    

            $ParamDictionary.Add('OnlyBasePolicies', [System.Management.Automation.RuntimeDefinedParameter]::new(
                    'OnlyBasePolicies',
                    [switch],
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
                    [switch],
                    [System.Management.Automation.ParameterAttribute[]]@($OnlySupplementalPoliciesDynamicParameter)
                ))           
           
            return $ParamDictionary
        }
    }

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { . Update-self }

       
        # Regular parameters are automatically bound to variables in the function scope
        # Dynamic parameters however, are only available in the parameter dictionary, which is why we have to access them using $PSBoundParameters 
        # or assign them manually to another variable in the function's scope
        $OnlyBasePolicies = $($PSBoundParameters['OnlyBasePolicies'])
        $OnlySupplementalPolicies = $($PSBoundParameters['OnlySupplementalPolicies']) 


        # Script block to show only non-system Base policies
        [scriptblock]$OnlyBasePoliciesBLOCK = {
            $BasePolicies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne 'True' } | Where-Object { $_.PolicyID -eq $_.BasePolicyID }           
            &$WriteLavender "`nThere are currently $(($BasePolicies.count)) Non-system Base policies deployed"
            $BasePolicies
        }
        # Script block to show only non-system Supplemental policies
        [scriptblock]$OnlySupplementalPoliciesBLOCK = {
            $SupplementalPolicies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne 'True' } | Where-Object { $_.PolicyID -ne $_.BasePolicyID }           
            &$WriteLavender "`nThere are currently $(($SupplementalPolicies.count)) Non-system Supplemental policies deployed`n"
            $SupplementalPolicies
        } 
        
        # If no main parameter was passed, run all of them
        if (!$ListActivePolicies -and !$VerifyWDACStatus -and !$CheckSmartAppControlStatus) {
            $ListActivePolicies = $true
            $VerifyWDACStatus = $true
            $CheckSmartAppControlStatus = $true
        }
    }

    process {
        if ($ListActivePolicies) {
            if ($OnlyBasePolicies) { &$OnlyBasePoliciesBLOCK }
            if ($OnlySupplementalPolicies) { &$OnlySupplementalPoliciesBLOCK }               
            if (!$OnlyBasePolicies -and !$OnlySupplementalPolicies) { &$OnlyBasePoliciesBLOCK; &$OnlySupplementalPoliciesBLOCK }
        }
        
        if ($VerifyWDACStatus) {
            Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -Property *codeintegrity* | Format-List
            &$WriteLavender "2 -> Enforced`n1 -> Audit mode`n0 -> Disabled/Not running`n"
        }

        if ($CheckSmartAppControlStatus) {
            Get-MpComputerStatus | Select-Object -Property SmartAppControlExpiration, SmartAppControlState
            if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
                &$WritePink "`nSmart App Control is in Evaluation mode."
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'On') {
                &$WritePink "`nSmart App Control is turned on."
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq 'Off') {
                &$WritePink "`nSmart App Control is turned off."
            }
        }            
    }
    
    <#
.SYNOPSIS
Show the status of WDAC on the system and lists the current deployed policies and shows details about each of them

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/Confirm-WDACConfig

.DESCRIPTION
Using official Microsoft methods, Show the status of WDAC (Windows Defender Application Control) on the system, list the current deployed policies and show details about each of them.

.COMPONENT
Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
Using official Microsoft methods, Show the status of WDAC (Windows Defender Application Control) on the system, list the current deployed policies and show details about each of them.

.PARAMETER ListActivePolicies
Lists the currently deployed policies and shows details about each of them

.PARAMETER VerifyWDACStatus
Shows the status of WDAC (Windows Defender Application Control) on the system

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

#> 
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
