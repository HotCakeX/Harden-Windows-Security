function Set-CommonWDACConfig {
    [CmdletBinding()]
    Param(
        [ValidateScript({
                [System.String[]]$Certificates = foreach ($cert in (Get-ChildItem -Path 'Cert:\CurrentUser\my')) {
            (($cert.Subject -split ',' | Select-Object -First 1) -replace 'CN=', '').Trim()
                }
                $Certificates -contains $_
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [parameter(Mandatory = $false)][System.String]$CertCN,

        [ValidatePattern('\.cer$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false)][System.String]$CertPath,

        [ValidatePattern('\.exe$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [parameter(Mandatory = $false)][System.String]$SignToolPath,

        [ValidatePattern('\.xml$')]
        [ValidateScript({
                $_ | ForEach-Object -Process {
                    $xmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if (!$RedFlag1 -and !$RedFlag2) {
                        return $True
                    }
                    else { throw 'The selected policy xml file is Signed, Please select an Unsigned policy.' }
                }
            }, ErrorMessage = 'The selected policy xml file is Signed, Please select an Unsigned policy.')]
        [parameter(Mandatory = $false)][System.String]$UnsignedPolicyPath,

        [ValidatePattern('\.xml$')]
        [ValidateScript({
                $_ | ForEach-Object -Process {
                    $xmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if ($RedFlag1 -or $RedFlag2) {
                        return $True
                    }
                    else { throw 'The selected policy xml file is Unsigned, Please select a Signed policy.' }
                }
            }, ErrorMessage = 'The selected policy xml file is Unsigned, Please select a Signed policy.')]
        [parameter(Mandatory = $false)][System.String]$SignedPolicyPath,

        [parameter(Mandatory = $false, DontShow = $true)][System.Guid]$StrictKernelPolicyGUID, # DontShow prevents common parameters from being displayed too

        [parameter(Mandatory = $false, DontShow = $true)][System.Guid]$StrictKernelNoFlightRootsPolicyGUID,

        [parameter(Mandatory = $false, DontShow = $true)][System.DateTime]$LastUpdateCheck
    )
    begin {
        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force -Verbose:$false

        # Create User configuration folder if it doesn't already exist
        if (-NOT (Test-Path -Path "$UserAccountDirectoryPath\.WDACConfig\")) {
            New-Item -ItemType Directory -Path "$UserAccountDirectoryPath\.WDACConfig\" -Force -ErrorAction Stop | Out-Null
            Write-Verbose -Message "The .WDACConfig folder in current user's folder has been created because it didn't exist."
        }

        # Create User configuration file if it doesn't already exist
        if (-NOT (Test-Path -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json")) {
            New-Item -ItemType File -Path "$UserAccountDirectoryPath\.WDACConfig\" -Name 'UserConfigurations.json' -Force -ErrorAction Stop | Out-Null
            Write-Verbose -Message "The UserConfigurations.json file in \.WDACConfig\ folder has been created because it didn't exist."
        }

        if ($PSBoundParameters.Count -eq 0) {
            Write-Error -Message 'No parameter was selected.'
            break
        }

        # Read the current user configurations
        $CurrentUserConfigurations = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"
        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            Set-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -Value ''
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
            $UserConfigurationsObject.SignedPolicyPath = $SignedPolicyPath
        }
        else {
            $UserConfigurationsObject.SignedPolicyPath = $CurrentUserConfigurations.SignedPolicyPath
        }

        if ($UnsignedPolicyPath) {
            $UserConfigurationsObject.UnsignedPolicyPath = $UnsignedPolicyPath
        }
        else {
            $UserConfigurationsObject.UnsignedPolicyPath = $CurrentUserConfigurations.UnsignedPolicyPath
        }

        if ($SignToolPath) {
            $UserConfigurationsObject.SignToolCustomPath = $SignToolPath
        }
        else {
            $UserConfigurationsObject.SignToolCustomPath = $CurrentUserConfigurations.SignToolCustomPath
        }

        if ($CertPath) {
            $UserConfigurationsObject.CertificatePath = $CertPath
        }
        else {
            $UserConfigurationsObject.CertificatePath = $CurrentUserConfigurations.CertificatePath
        }

        if ($CertCN) {
            $UserConfigurationsObject.CertificateCommonName = $CertCN
        }
        else {
            $UserConfigurationsObject.CertificateCommonName = $CurrentUserConfigurations.CertificateCommonName
        }

        if ($StrictKernelPolicyGUID) {
            $UserConfigurationsObject.StrictKernelPolicyGUID = $StrictKernelPolicyGUID
        }
        else {
            $UserConfigurationsObject.StrictKernelPolicyGUID = $CurrentUserConfigurations.StrictKernelPolicyGUID
        }

        if ($StrictKernelNoFlightRootsPolicyGUID) {
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $StrictKernelNoFlightRootsPolicyGUID
        }
        else {
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID
        }

        if ($LastUpdateCheck) {
            $UserConfigurationsObject.LastUpdateCheck = $LastUpdateCheck
        }
        else {
            $UserConfigurationsObject.LastUpdateCheck = $CurrentUserConfigurations.LastUpdateCheck
        }
    }
    end {
        # Update the User Configurations file
        $UserConfigurationsObject | ConvertTo-Json | Set-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"
        Write-ColorfulText -Color Pink -InputText "`nThis is your new WDAC User Configurations: "
        Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" | ConvertFrom-Json | Format-List -Property *
    }
}
<#
.SYNOPSIS
    Add/Change common values for parameters used by WDACConfig module

.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Set-CommonWDACConfig

.DESCRIPTION
    Add/Change common values for parameters used by WDACConfig module so that you won't have to provide values for those repetitive parameters each time you need to use the WDACConfig module cmdlets.

.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module, WDACConfig module

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

.PARAMETER StrictKernelPolicyGUID
    GUID of the Strict Kernel mode policy

.PARAMETER StrictKernelNoFlightRootsPolicyGUID
    GUID of the Strict Kernel no Flights root mode policy

#>

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'CertCN' -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'CertPath' -ScriptBlock $ArgumentCompleterCerFilePathsPicker
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignedPolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'UnsignedPolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
