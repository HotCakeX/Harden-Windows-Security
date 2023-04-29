#Requires -RunAsAdministrator
function Confirm-WDACConfig {
    [CmdletBinding(
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig"
    )]
    Param(     
        [Parameter(Mandatory = $false, ParameterSetName = "List Active Policies")][switch]$ListActivePolicies,
        [Parameter(Mandatory = $false, ParameterSetName = "Verify WDAC Status")][switch]$VerifyWDACStatus,
        [Parameter(Mandatory = $false, ParameterSetName = "Check SmartAppControl Status")][switch]$CheckSmartAppControlStatus,

        [Parameter(Mandatory = $false, ParameterSetName = "List Active Policies")][switch]$OnlyBasePolicies,
        [Parameter(Mandatory = $false, ParameterSetName = "List Active Policies")][switch]$OnlySupplementalPolicies,
        
        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error, anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { . Update-self }

        # Script block to show only non-system Supplemental policies
        $OnlySupplementalPoliciesBLOCK = { Write-host "`nDisplaying non-System Supplemental WDAC Policies:" -ForegroundColor Cyan
            $SupplementalPolicies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.PolicyID -ne $_.BasePolicyID } ; $SupplementalPolicies           
            Write-Host "There are currently $(($SupplementalPolicies.count)) Non-system Supplemental policies deployed." -ForegroundColor Green }
        # Script block to show only non-system Base policies
        $OnlyBasePoliciesBLOCK = { Write-host "`nDisplaying non-System Base WDAC Policies:" -ForegroundColor Cyan
            $BasePolicies = (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.PolicyID -eq $_.BasePolicyID } ; $BasePolicies           
            Write-Host "There are currently $(($BasePolicies.count)) Non-system Base policies deployed." -ForegroundColor Green }
    }

    process {
        if ($ListActivePolicies) {
            if ($OnlyBasePolicies) { &$OnlyBasePoliciesBLOCK }
            if ($OnlySupplementalPolicies) { &$OnlySupplementalPoliciesBLOCK }               
            if (-NOT $OnlyBasePolicies -and -NOT$OnlySupplementalPolicies) { &$OnlyBasePoliciesBLOCK; &$OnlySupplementalPoliciesBLOCK }
        }
        
        if ($VerifyWDACStatus) {
            Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -Property *codeintegrity* | Format-List
            Write-host "2 -> Enforced`n1 -> Audit mode`n0 -> Disabled/Not running`n" -ForegroundColor Cyan
        }

        if ($CheckSmartAppControlStatus) {
            Get-MpComputerStatus | Select-Object -Property SmartAppControlExpiration, SmartAppControlState
            if ((Get-MpComputerStatus).SmartAppControlState -eq "Eval") {
                Write-Host "Smart App Control is in Evaluation mode.`n"
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq "On") {
                Write-Host "Smart App Control is turned on.`n"
            }
            elseif ((Get-MpComputerStatus).SmartAppControlState -eq "Off") {
                Write-Host "Smart App Control is turned off.`n"
            }
        }    
    }
    
    <#
.SYNOPSIS
Show the status of WDAC on the system and lists the current deployed policies and shows details about each of them

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig

.DESCRIPTION
Using official Microsoft methods, Show the status of WDAC on the system and lists the current deployed policies and shows details about each of them (Windows Defender Application Control)

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Using official Microsoft methods, Show the status of WDAC on the system and lists the current deployed policies and shows details about each of them (Windows Defender Application Control)

.PARAMETER VerifyWDACStatus
Shows the status of WDAC on the system

.PARAMETER ListActivePolicies
lists the current deployed policies and shows details about each of them

.PARAMETER $CheckSmartAppControlStatus
Checks the status of Smart App Control and reports the results on the console

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#> 
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete