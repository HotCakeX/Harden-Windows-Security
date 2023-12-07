function Remove-CommonWDACConfig {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertCN,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignToolPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$UnsignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$LastUpdateCheck # DontShow prevents common parameters from being displayed too
    )
    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$ModuleRootPath\Resources\Resources.ps1"

        # Fetch User account directory path
        [System.String]$global:UserAccountDirectoryPath = (Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath

        # Create User configuration folder if it doesn't already exist
        if (-NOT (Test-Path -Path "$global:UserAccountDirectoryPath\.WDACConfig\")) {
            New-Item -ItemType Directory -Path "$global:UserAccountDirectoryPath\.WDACConfig\" -Force -ErrorAction Stop | Out-Null
            Write-Debug -Message "The .WDACConfig folder in current user's folder has been created because it didn't exist."
        }

        # Create User configuration file if it doesn't already exist
        if (-NOT (Test-Path -Path "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json")) {
            New-Item -ItemType File -Path "$global:UserAccountDirectoryPath\.WDACConfig\" -Name 'UserConfigurations.json' -Force -ErrorAction Stop | Out-Null
            Write-Debug -Message "The UserConfigurations.json file in \.WDACConfig\ folder has been created because it didn't exist."
        }

        # Delete the entire User Configs if a more specific parameter wasn't used
        if ($PSBoundParameters.Count -eq 0) {
            Remove-Item -Path "$global:UserAccountDirectoryPath\.WDACConfig\" -Recurse -Force
            &$WritePink 'User Configurations for WDACConfig module have been deleted.'
            break
        }

        # Read the current user configurations
        $CurrentUserConfigurations = Get-Content -Path "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"
        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            Set-Content -Path "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -Value ''
        }

        # An object to hold the User configurations
        $UserConfigurationsObject = [PSCustomObject]@{
            SignedPolicyPath                    = ''
            UnsignedPolicyPath                  = ''
            SignToolCustomPath                  = ''
            CertificateCommonName               = ''
            CertificatePath                     = ''
            StrictKernelPolicyGUID              = ''
            StrictKernelNoFlightRootsPolicyGUID = ''
            LastUpdateCheck                     = ''
        }
    }
    process {
        if ($SignedPolicyPath) {
            $UserConfigurationsObject.SignedPolicyPath = ''
        }
        else {
            $UserConfigurationsObject.SignedPolicyPath = $CurrentUserConfigurations.SignedPolicyPath
        }

        if ($UnsignedPolicyPath) {
            $UserConfigurationsObject.UnsignedPolicyPath = ''
        }
        else {
            $UserConfigurationsObject.UnsignedPolicyPath = $CurrentUserConfigurations.UnsignedPolicyPath
        }

        if ($SignToolPath) {
            $UserConfigurationsObject.SignToolCustomPath = ''
        }
        else {
            $UserConfigurationsObject.SignToolCustomPath = $CurrentUserConfigurations.SignToolCustomPath
        }

        if ($CertPath) {
            $UserConfigurationsObject.CertificatePath = ''
        }
        else {
            $UserConfigurationsObject.CertificatePath = $CurrentUserConfigurations.CertificatePath
        }

        if ($CertCN) {
            $UserConfigurationsObject.CertificateCommonName = ''
        }
        else {
            $UserConfigurationsObject.CertificateCommonName = $CurrentUserConfigurations.CertificateCommonName
        }

        if ($StrictKernelPolicyGUID) {
            $UserConfigurationsObject.StrictKernelPolicyGUID = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelPolicyGUID = $CurrentUserConfigurations.StrictKernelPolicyGUID
        }

        if ($StrictKernelNoFlightRootsPolicyGUID) {
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID
        }

        if ($LastUpdateCheck) {
            $UserConfigurationsObject.LastUpdateCheck = ''
        }
        else {
            $UserConfigurationsObject.LastUpdateCheck = $CurrentUserConfigurations.LastUpdateCheck
        }
    }
    end {
        # Update the User Configurations file
        $UserConfigurationsObject | ConvertTo-Json | Set-Content "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"
        &$WritePink "`nThis is your new WDAC User Configurations: "
        Get-Content -Path "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" | ConvertFrom-Json | Format-List *
    }
}
<#
.SYNOPSIS
    Removes common values for parameters used by WDACConfig module

.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Remove-CommonWDACConfig

.DESCRIPTION
    Removes common values for parameters used by WDACConfig module from the User Configurations JSON file. If you don't use it with any parameters, then all User Configs will be deleted.

.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module, WDACConfig module

.FUNCTIONALITY
    Removes common values for parameters used by WDACConfig module from the User Configurations JSON file. If you don't use it with any parameters, then all User Configs will be deleted.

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

#>
