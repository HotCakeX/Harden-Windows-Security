Function Get-CommonWDACConfig {
    [CmdletBinding()]
    Param(
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertCN,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignToolPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$UnsignedPolicyPath,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$StrictKernelPolicyGUID, # DontShow prevents common parameters from being displayed too
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Open,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$LastUpdateCheck
    )
    begin {
        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"
        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force

        # Create User configuration folder if it doesn't already exist
        if (-NOT (Test-Path -Path "$UserAccountDirectoryPath\.WDACConfig\")) {
            New-Item -ItemType Directory -Path "$UserAccountDirectoryPath\.WDACConfig\" -Force -ErrorAction Stop | Out-Null
            Write-Debug -Message "The .WDACConfig folder in current user's folder has been created because it didn't exist."
        }

        # Create User configuration file if it doesn't already exist
        if (-NOT (Test-Path -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json")) {
            New-Item -ItemType File -Path "$UserAccountDirectoryPath\.WDACConfig\" -Name 'UserConfigurations.json' -Force -ErrorAction Stop | Out-Null
            Write-Debug -Message "The UserConfigurations.json file in \.WDACConfig\ folder has been created because it didn't exist."
        }

        if ($Open) {
            . "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"
            break
        }

        if ($PSBoundParameters.Count -eq 0) {
            # Display this message if User Configuration file is empty
            if ($null -eq (Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json")) {
                Write-ColorfulText -Color Pink -InputText "`nYour current WDAC User Configurations is empty."
            }
            # Display this message if User Configuration file has content
            else {
                Write-ColorfulText -Color Pink -InputText "`nThis is your current WDAC User Configurations: "
                Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" | ConvertFrom-Json | Format-List -Property *
            }
            break
        }

        # Read the current user configurations
        [PSCustomObject]$CurrentUserConfigurations = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"
        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            Write-Warning 'The UserConfigurations.json was corrupted, clearing it.'
            Set-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -Value ''
        }
    }

    process {}

    end {
        # Use a switch statement to check which parameter is present and output the corresponding value from the json file
        switch ($true) {
            $SignedPolicyPath.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.SignedPolicyPath }
            $UnsignedPolicyPath.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.UnsignedPolicyPath }
            $SignToolPath.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.SignToolCustomPath }
            $CertCN.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.CertificateCommonName }
            $StrictKernelPolicyGUID.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.StrictKernelPolicyGUID }
            $StrictKernelNoFlightRootsPolicyGUID.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID }
            $CertPath.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.CertificatePath }
            $LastUpdateCheck.IsPresent { Write-Output -InputObject $CurrentUserConfigurations.LastUpdateCheck }
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

.INPUTS
    None. You cannot pipe objects to this function.

.OUTPUTS
    System.Object[]
#>
