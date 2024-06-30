Function Remove-CommonWDACConfig {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]
    Param(
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertCN,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignToolPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$UnsignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$LastUpdateCheck,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelModePolicyTimeOfDeployment,
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Force
    )
    begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        # Create User configuration folder if it doesn't already exist
        if (-NOT ([System.IO.Directory]::Exists((Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Parent)))) {
            $null = New-Item -ItemType Directory -Path (Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Parent) -Force
            Write-Verbose -Message 'The WDACConfig folder in Program Files has been created because it did not exist.'
        }

        # Create User configuration file if it doesn't already exist
        if (-NOT ([System.IO.File]::Exists(([WDACConfig.GlobalVars]::UserConfigJson)))) {
            $null = New-Item -ItemType File -Path (Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Parent) -Name (Split-Path -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Leaf) -Force
            Write-Verbose -Message 'The UserConfigurations.json file has been created because it did not exist.'
        }

        # Detecting if Confirm switch is used to bypass the confirmation prompts
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }

        # Delete the entire User Configs if a more specific parameter wasn't used
        # This method is better than $PSBoundParameters since it also contains common parameters
        if (!$CertCN -And !$CertPath -And !$SignToolPath -And !$UnsignedPolicyPath -And !$SignedPolicyPath -And !$StrictKernelPolicyGUID -And !$StrictKernelNoFlightRootsPolicyGUID -And !$LastUpdateCheck -And !$StrictKernelModePolicyTimeOfDeployment) {

            # Prompt for confirmation before deleting the entire User Configurations
            if ($PSCmdlet.ShouldProcess('This PC', 'Delete the entire User Configurations for WDACConfig module')) {

                Remove-Item -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Force
                Write-Verbose -Message 'User Configurations for WDACConfig module have been deleted.'
            }

            # set a boolean value that returns from the Process and End blocks as well
            [System.Boolean]$ReturnAndDone = $true
            # Exit the begin block
            Return
        }

        # Read the current user configurations
        [System.Object[]]$CurrentUserConfigurations = Get-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson)

        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            $CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json
        }
        catch {
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
        # Exit the process block
        if ($true -eq $ReturnAndDone) { return }

        if ($SignedPolicyPath) {
            Write-Verbose -Message 'Removing the SignedPolicyPath'
            $UserConfigurationsObject.SignedPolicyPath = ''
        }
        else {
            $UserConfigurationsObject.SignedPolicyPath = $CurrentUserConfigurations.SignedPolicyPath
        }

        if ($UnsignedPolicyPath) {
            Write-Verbose -Message 'Removing the UnsignedPolicyPath'
            $UserConfigurationsObject.UnsignedPolicyPath = ''
        }
        else {
            $UserConfigurationsObject.UnsignedPolicyPath = $CurrentUserConfigurations.UnsignedPolicyPath
        }

        if ($SignToolPath) {
            Write-Verbose -Message 'Removing the SignToolPath'
            $UserConfigurationsObject.SignToolCustomPath = ''
        }
        else {
            $UserConfigurationsObject.SignToolCustomPath = $CurrentUserConfigurations.SignToolCustomPath
        }

        if ($CertPath) {
            Write-Verbose -Message 'Removing the CertPath'
            $UserConfigurationsObject.CertificatePath = ''
        }
        else {
            $UserConfigurationsObject.CertificatePath = $CurrentUserConfigurations.CertificatePath
        }

        if ($CertCN) {
            Write-Verbose -Message 'Removing the CertCN'
            $UserConfigurationsObject.CertificateCommonName = ''
        }
        else {
            $UserConfigurationsObject.CertificateCommonName = $CurrentUserConfigurations.CertificateCommonName
        }

        if ($StrictKernelPolicyGUID) {
            Write-Verbose -Message 'Removing the StrictKernelPolicyGUID'
            $UserConfigurationsObject.StrictKernelPolicyGUID = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelPolicyGUID = $CurrentUserConfigurations.StrictKernelPolicyGUID
        }

        if ($StrictKernelNoFlightRootsPolicyGUID) {
            Write-Verbose -Message 'Removing the StrictKernelNoFlightRootsPolicyGUID'
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelNoFlightRootsPolicyGUID = $CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID
        }

        if ($LastUpdateCheck) {
            Write-Verbose -Message 'Removing the LastUpdateCheck'
            $UserConfigurationsObject.LastUpdateCheck = ''
        }
        else {
            $UserConfigurationsObject.LastUpdateCheck = $CurrentUserConfigurations.LastUpdateCheck
        }

        if ($StrictKernelModePolicyTimeOfDeployment) {
            Write-Verbose -Message 'Removing the Strict Kernel-Mode Policy Time Of Deployment'
            $UserConfigurationsObject.StrictKernelModePolicyTimeOfDeployment = ''
        }
        else {
            $UserConfigurationsObject.StrictKernelModePolicyTimeOfDeployment = $CurrentUserConfigurations.StrictKernelModePolicyTimeOfDeployment
        }
    }
    end {
        # Exit the end block
        if ($true -eq $ReturnAndDone) { return }

        $UserConfigurationsJSON = $UserConfigurationsObject | ConvertTo-Json

        try {
            Write-Verbose -Message 'Validating the JSON against the schema'
            [System.Boolean]$IsValid = Test-Json -Json $UserConfigurationsJSON -SchemaFile "$([WDACConfig.GlobalVars]::ModuleRootPath)\Resources\User Configurations\Schema.json"
        }
        catch {
            Write-Warning -Message "$_`nclearing it."
            Set-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Value '' -Force
        }

        if ($IsValid) {
            # Update the User Configurations file
            Write-Verbose -Message 'Saving the changes'
            $UserConfigurationsJSON | Set-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Force
        }
        else {
            Throw 'The User Configurations file is not valid.'
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
.PARAMETER LastUpdateCheck
    Using DontShow for this parameter which prevents common parameters from being displayed too
.PARAMETER StrictKernelModePolicyTimeOfDeployment
    Removes the StrictKernelModePolicyTimeOfDeployment from User Configs
.INPUTS
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    Remove-CoreWDACConfig -CertCN
.EXAMPLE
    Remove-CoreWDACConfig -CertPath
.EXAMPLE
    Remove-CoreWDACConfig
#>
}
