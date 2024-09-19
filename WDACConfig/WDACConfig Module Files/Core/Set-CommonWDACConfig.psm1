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
        [parameter(Mandatory = $false)][System.IO.FileInfo]$SignedPolicyPath,

        [parameter(Mandatory = $false, DontShow = $true)][System.Guid]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.Guid]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.DateTime]$LastUpdateCheck,
        [parameter(Mandatory = $false)][System.DateTime]$StrictKernelModePolicyTimeOfDeployment
    )
    begin {
        if ($(Get-PSCallStack).Count -le 2) {
            [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        }
        else {
            [WDACConfig.LoggerInitializer]::Initialize($null, $null, $Host)
        }
        if (!$CertCN -And !$CertPath -And !$SignToolPath -And !$UnsignedPolicyPath -And !$SignedPolicyPath -And !$StrictKernelPolicyGUID -And !$StrictKernelNoFlightRootsPolicyGUID -And !$LastUpdateCheck -And !$StrictKernelModePolicyTimeOfDeployment) {
            Throw [System.ArgumentException] 'No parameter was selected.'
        }

        if ($CertCN) {
            if ([WDACConfig.CertCNz]::new().GetValidValues() -notcontains $CertCN) {
                throw "$CertCN does not belong to a subject CN of any of the deployed certificates"
            }
        }

        # Create User configuration folder if it doesn't already exist
        if (-NOT ([System.IO.Directory]::Exists((Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Parent)))) {
            $null = New-Item -ItemType Directory -Path (Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Parent) -Force
            [WDACConfig.Logger]::Write('The WDACConfig folder in Program Files has been created because it did not exist.')
        }

        # Create User configuration file if it doesn't already exist
        if (-NOT ([System.IO.File]::Exists(([WDACConfig.GlobalVars]::UserConfigJson)))) {
            $null = New-Item -ItemType File -Path (Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Parent) -Name (Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Leaf) -Force
            [WDACConfig.Logger]::Write('The UserConfigurations.json file has been created because it did not exist.')
        }

        # Trying to read the current user configurations
        [WDACConfig.Logger]::Write('Trying to read the current user configurations')
        [System.Object[]]$CurrentUserConfigurations = Get-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson)

        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
            [WDACConfig.Logger]::Write('The user configurations file exists but is corrupted and has bad values, rewriting it')
            Set-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Value ''
        }

        # A hashtable to hold the User configurations
        [System.Collections.Hashtable]$UserConfigurationsObject = @{
            SignedPolicyPath                       = ''
            UnsignedPolicyPath                     = ''
            SignToolCustomPath                     = ''
            CertificateCommonName                  = ''
            CertificatePath                        = ''
            StrictKernelPolicyGUID                 = ''
            StrictKernelNoFlightRootsPolicyGUID    = ''
            LastUpdateCheck                        = ''
            StrictKernelModePolicyTimeOfDeployment = ''
        }
    }
    process {

        [WDACConfig.Logger]::Write('Processing each user configuration property')

        if ($SignedPolicyPath) {
            [WDACConfig.Logger]::Write('Saving the supplied Signed Policy path in user configurations.')
            $UserConfigurationsObject.SignedPolicyPath = $SignedPolicyPath.FullName
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Signed Policy path property was detected.')
            $UserConfigurationsObject.SignedPolicyPath = $CurrentUserConfigurations.SignedPolicyPath
        }

        if ($UnsignedPolicyPath) {
            [WDACConfig.Logger]::Write('Saving the supplied Unsigned Policy path in user configurations.')
            $UserConfigurationsObject.UnsignedPolicyPath = $UnsignedPolicyPath.FullName
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Unsigned Policy path property was detected.')
            $UserConfigurationsObject.UnsignedPolicyPath = $CurrentUserConfigurations.UnsignedPolicyPath
        }

        if ($SignToolPath) {
            [WDACConfig.Logger]::Write('Saving the supplied SignTool path in user configurations.')
            $UserConfigurationsObject.SignToolCustomPath = $SignToolPath.FullName
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Signtool path property was detected.')
            $UserConfigurationsObject.SignToolCustomPath = $CurrentUserConfigurations.SignToolCustomPath
        }

        if ($CertPath) {
            [WDACConfig.Logger]::Write('Saving the supplied Certificate path in user configurations.')
            $UserConfigurationsObject.CertificatePath = $CertPath.FullName
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Certificate path property was detected.')
            $UserConfigurationsObject.CertificatePath = $CurrentUserConfigurations.CertificatePath
        }

        if ($CertCN) {
            [WDACConfig.Logger]::Write('Saving the supplied Certificate common name in user configurations.')
            $UserConfigurationsObject.CertificateCommonName = $CertCN
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Certificate common name property was detected.')
            $UserConfigurationsObject.CertificateCommonName = $CurrentUserConfigurations.CertificateCommonName
        }

        if ($StrictKernelPolicyGUID) {
            [WDACConfig.Logger]::Write('Saving the supplied Strict Kernel policy GUID in user configurations.')
            $UserConfigurationsObject.StrictKernelPolicyGUID = $StrictKernelPolicyGUID
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Strict Kernel policy GUID property was detected.')
            $UserConfigurationsObject.StrictKernelPolicyGUID = $CurrentUserConfigurations.StrictKernelPolicyGUID
        }

        if ($StrictKernelNoFlightRootsPolicyGUID) {
            [WDACConfig.Logger]::Write('Saving the supplied Strict Kernel NoFlightRoot policy GUID in user configurations.')
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $StrictKernelNoFlightRootsPolicyGUID
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Strict Kernel NoFlightRoot policy GUID property was detected.')
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID
        }

        if ($LastUpdateCheck) {
            [WDACConfig.Logger]::Write('Saving the supplied Last Update Check in user configurations.')
            $UserConfigurationsObject.LastUpdateCheck = $LastUpdateCheck
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Last Update Check property was detected.')
            $UserConfigurationsObject.LastUpdateCheck = $CurrentUserConfigurations.LastUpdateCheck
        }

        if ($StrictKernelModePolicyTimeOfDeployment) {
            [WDACConfig.Logger]::Write('Saving the supplied Strict Kernel-Mode Policy Time Of Deployment in user configurations.')
            $UserConfigurationsObject.StrictKernelModePolicyTimeOfDeployment = $StrictKernelModePolicyTimeOfDeployment
        }
        else {
            [WDACConfig.Logger]::Write('No changes to the Strict Kernel-Mode Policy Time Of Deployment property was detected.')
            $UserConfigurationsObject.StrictKernelModePolicyTimeOfDeployment = $CurrentUserConfigurations.StrictKernelModePolicyTimeOfDeployment
        }
    }
    end {

        $UserConfigurationsJSON = $UserConfigurationsObject | ConvertTo-Json

        try {
            [WDACConfig.Logger]::Write('Validating the JSON against the schema')
            [System.Boolean]$IsValid = Test-Json -Json $UserConfigurationsJSON -SchemaFile "$([WDACConfig.GlobalVars]::ModuleRootPath)\Resources\User Configurations\Schema.json"
        }
        catch {
            Write-Warning -Message "$_`nclearing it."
            Set-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Value '' -Force
        }

        if ($IsValid) {
            # Update the User Configurations file
            [WDACConfig.Logger]::Write('Saving the changes')
            $UserConfigurationsJSON | Set-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Force

            # Display the updated User Configurations
            $UserConfigurationsObject
        }
        else {
            Throw 'The User Configurations file is not valid.'
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
.PARAMETER LastUpdateCheck
    Last time the Update policy was checked for updates
    Used internally by the module
.PARAMETER StrictKernelModePolicyTimeOfDeployment
    Time of deployment of the Strict Kernel-Mode policy
    Used internally by the module
.INPUTS
    System.IO.FileInfo
    System.DateTime
    System.Guid
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
