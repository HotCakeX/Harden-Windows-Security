Function Set-CommonWDACConfig {
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
            Throw 'No parameter was selected.'
        }

        # Trying to read the current user configurations
        Write-Verbose -Message 'Trying to read the current user configurations'
        [System.Object[]]$CurrentUserConfigurations = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"

        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            Write-Verbose -Message 'The user configurations file exists but is corrupted and has bad values, rewriting it'
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

        Write-Verbose -Message 'Processing each user configuration property'

        if ($SignedPolicyPath) {
            Write-Verbose -Message 'Saving the supplied Signed Policy path in user configurations.'
            $UserConfigurationsObject.SignedPolicyPath = $SignedPolicyPath
        }
        else {
            Write-Verbose -Message 'No changes to the Signed Policy path property was detected.'
            $UserConfigurationsObject.SignedPolicyPath = $CurrentUserConfigurations.SignedPolicyPath
        }

        if ($UnsignedPolicyPath) {
            Write-Verbose -Message 'Saving the supplied Unsigned Policy path in user configurations.'
            $UserConfigurationsObject.UnsignedPolicyPath = $UnsignedPolicyPath
        }
        else {
            Write-Verbose -Message 'No changes to the Unsigned Policy path property was detected.'
            $UserConfigurationsObject.UnsignedPolicyPath = $CurrentUserConfigurations.UnsignedPolicyPath
        }

        if ($SignToolPath) {
            Write-Verbose -Message 'Saving the supplied SignTool path in user configurations.'
            $UserConfigurationsObject.SignToolCustomPath = $SignToolPath
        }
        else {
            Write-Verbose -Message 'No changes to the Signtool path property was detected.'
            $UserConfigurationsObject.SignToolCustomPath = $CurrentUserConfigurations.SignToolCustomPath
        }

        if ($CertPath) {
            Write-Verbose -Message 'Saving the supplied Certificate path in user configurations.'
            $UserConfigurationsObject.CertificatePath = $CertPath
        }
        else {
            Write-Verbose -Message 'No changes to the Certificate path property was detected.'
            $UserConfigurationsObject.CertificatePath = $CurrentUserConfigurations.CertificatePath
        }

        if ($CertCN) {
            Write-Verbose -Message 'Saving the supplied Certificate common name in user configurations.'
            $UserConfigurationsObject.CertificateCommonName = $CertCN
        }
        else {
            Write-Verbose -Message 'No changes to the Certificate common name property was detected.'
            $UserConfigurationsObject.CertificateCommonName = $CurrentUserConfigurations.CertificateCommonName
        }

        if ($StrictKernelPolicyGUID) {
            Write-Verbose -Message 'Saving the supplied Strict Kernel policy GUID in user configurations.'
            $UserConfigurationsObject.StrictKernelPolicyGUID = $StrictKernelPolicyGUID
        }
        else {
            Write-Verbose -Message 'No changes to the Strict Kernel policy GUID property was detected.'
            $UserConfigurationsObject.StrictKernelPolicyGUID = $CurrentUserConfigurations.StrictKernelPolicyGUID
        }

        if ($StrictKernelNoFlightRootsPolicyGUID) {
            Write-Verbose -Message 'Saving the supplied Strict Kernel NoFlightRoot policy GUID in user configurations.'
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $StrictKernelNoFlightRootsPolicyGUID
        }
        else {
            Write-Verbose -Message 'No changes to the Strict Kernel NoFlightRoot policy GUID property was detected.'
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID
        }

        if ($LastUpdateCheck) {
            Write-Verbose -Message 'Saving the supplied Last Update Check in user configurations.'
            $UserConfigurationsObject.LastUpdateCheck = $LastUpdateCheck
        }
        else {
            Write-Verbose -Message 'No changes to the Last Update Check property was detected.'
            $UserConfigurationsObject.LastUpdateCheck = $CurrentUserConfigurations.LastUpdateCheck
        }
    }
    end {
        # Update the User Configurations file
        Write-Verbose -Message 'Saving the changes'
        $UserConfigurationsObject | ConvertTo-Json | Set-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json"
        Write-ColorfulText -Color Pink -InputText "`nThis is your new WDAC User Configurations: "

        Write-Verbose -Message 'Displaying the current user configurations'
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

.INPUTS
    System.DateTime
    System.Guid
    System.String

.OUTPUTS
    System.Object[]
#>

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'CertCN' -ScriptBlock $ArgumentCompleterCertificateCN
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'CertPath' -ScriptBlock $ArgumentCompleterCerFilePathsPicker
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'SignedPolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'Set-CommonWDACConfig' -ParameterName 'UnsignedPolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
