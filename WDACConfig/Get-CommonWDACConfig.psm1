#Requires -RunAsAdministrator
function Get-CommonWDACConfig {
    [CmdletBinding()]
    Param(       
        [parameter(Mandatory = $false)][switch]$SignedPolicyPath,
        [parameter(Mandatory = $false)][switch]$UnsignedPolicyPath,
        [parameter(Mandatory = $false)][switch]$SignToolPath,
        [parameter(Mandatory = $false)][switch]$CertCN,
        [parameter(Mandatory = $false)][switch]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false)][switch]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false)][switch]$CertPath,
        [parameter(Mandatory = $false)][switch]$Open,
        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck
    )
    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"
        
        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'        
        if (-NOT $SkipVersionCheck) { . Update-self }
        
        # Scan the file with Microsoft Defender for anything malicious before it's going to be used
        Start-MpScan -ScanType CustomScan -ScanPath "$env:USERPROFILE\.WDACConfig\UserConfigurations.json"

        if ($Open) {        
            . "$env:USERPROFILE\.WDACConfig\UserConfigurations.json"
            break
        }        

        if ($PSBoundParameters.Count -eq 0) {
            &$WritePink "`nThis is your current WDAC User Configurations: "
            Get-Content -Path "$env:USERPROFILE\.WDACConfig\UserConfigurations.json" | ConvertFrom-Json | Format-List *
            break
        }

        # Read the current user configurations
        [PSCustomObject]$CurrentUserConfigurations = Get-Content -Path "$env:USERPROFILE\.WDACConfig\UserConfigurations.json"
        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            Write-Warning 'The UserConfigurations.json was corrupted, clearing it.'
            Set-Content -Path "$env:USERPROFILE\.WDACConfig\UserConfigurations.json" -Value ''
        }        
    }

    process {}

    end {
        # Use a switch statement to check which parameter is present and output the corresponding value from the json file
        switch ($true) {
            $SignedPolicyPath.IsPresent { Write-Output $CurrentUserConfigurations.SignedPolicyPath }
            $UnsignedPolicyPath.IsPresent { Write-Output $CurrentUserConfigurations.UnsignedPolicyPath }
            $SignToolPath.IsPresent { Write-Output $CurrentUserConfigurations.SignToolCustomPath }
            $CertCN.IsPresent { Write-Output $CurrentUserConfigurations.CertificateCommonName }
            $StrictKernelPolicyGUID.IsPresent { Write-Output $CurrentUserConfigurations.StrictKernelPolicyGUID }            
            $StrictKernelNoFlightRootsPolicyGUID.IsPresent { Write-Output $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID }
            $CertPath.IsPresent { Write-Output $CurrentUserConfigurations.CertificatePath }
        }
    }
}

<#
.SYNOPSIS
Query and Read common values for parameters used by WDACConfig module

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CommonWDACConfig

.DESCRIPTION
Reads and gets the values from the User Config Json file, used by the module internally and also to display the values on the console for the user

.COMPONENT
Windows Defender Application Control, ConfigCI PowerShell module, WDACConfig module

.FUNCTIONALITY
Reads and gets the values from the User Config Json file, used by the module internally and also to display the values on the console for the user

.PARAMETER SignedPolicyPath
Shows the path to a Signed WDAC xml policy

.PARAMETER UnsignedPolicyPath
Shows the  path to an Unsigned WDAC xml policy

.PARAMETER CertCN
Shows the certificate common name

.PARAMETER SignToolPath
Shows the  path to the SignTool.exe

.PARAMETER CertPath
Shows the path to a .cer certificate file

.PARAMETER Open
Opens the User Configuration file with the default app assigned to open Json files

.PARAMETER StrictKernelPolicyGUID
Shows the GUID of the Strict Kernel mode policy

.PARAMETER StrictKernelNoFlightRootsPolicyGUID
Shows the GUID of the Strict Kernel no Flights root mode policy

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
