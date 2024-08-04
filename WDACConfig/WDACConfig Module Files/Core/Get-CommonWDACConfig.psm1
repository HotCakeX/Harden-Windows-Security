Function Get-CommonWDACConfig {
    [CmdletBinding()]
    [OutputType([System.Object[]], [System.DateTime], [System.String], [System.Guid])]
    Param(
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertCN,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$CertPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignToolPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SignedPolicyPath,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$UnsignedPolicyPath,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$StrictKernelPolicyGUID,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$StrictKernelNoFlightRootsPolicyGUID,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Open,
        [parameter(Mandatory = $false, DontShow = $true)][System.Management.Automation.SwitchParameter]$LastUpdateCheck,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$StrictKernelModePolicyTimeOfDeployment
    )
    begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        if ($(Get-PSCallStack).Count -le 2) {
            [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        }
        else {
            [WDACConfig.LoggerInitializer]::Initialize($null, $null, $Host)
        }
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

        if ($Open) {
            . ([WDACConfig.GlobalVars]::UserConfigJson)

            # set a boolean value that returns from the Process and End blocks as well
            [System.Boolean]$ReturnAndDone = $true
            # return/exit from the begin block
            Return
        }

        # Display this message if User Configuration file is empty or only has spaces/new lines
        if ([System.String]::IsNullOrWhiteSpace((Get-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson)))) {
            Write-Verbose -Message 'Your current WDAC User Configurations is empty.'

            [System.Boolean]$ReturnAndDone = $true
            # return/exit from the begin block
            Return
        }

        Write-Verbose -Message 'Reading the current user configurations'
        [System.Object[]]$CurrentUserConfigurations = Get-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Force

        # If the file exists but is corrupted and has bad values, rewrite it
        try {
            [System.Collections.Hashtable]$CurrentUserConfigurations = $CurrentUserConfigurations | ConvertFrom-Json -AsHashtable
        }
        catch {
            Write-Warning -Message 'The UserConfigurations.json was corrupted, clearing it.'
            Set-Content -Path ([WDACConfig.GlobalVars]::UserConfigJson) -Value ''

            [System.Boolean]$ReturnAndDone = $true
            # return/exit from the begin block
            Return
        }
    }

    process {
        # return/exit from the process block
        if ($true -eq $ReturnAndDone) { return }

        # Remove any empty values from the hashtable
        foreach ($Item in @($CurrentUserConfigurations.keys)) {
            if (!$CurrentUserConfigurations[$Item]) {
                $CurrentUserConfigurations.Remove($Item)
            }
        }
    }

    end {
        # return/exit from the end block
        if ($true -eq $ReturnAndDone) { return }

        # Use a switch statement to check which parameter is present and output the corresponding value from the json file
        switch ($true) {
            $SignedPolicyPath.IsPresent { return ($CurrentUserConfigurations.SignedPolicyPath ?? $null) }
            $UnsignedPolicyPath.IsPresent { return ($CurrentUserConfigurations.UnsignedPolicyPath ?? $null) }
            $SignToolPath.IsPresent { return ($CurrentUserConfigurations.SignToolCustomPath ?? $null) }
            $CertCN.IsPresent { return ($CurrentUserConfigurations.CertificateCommonName ?? $null) }
            $StrictKernelPolicyGUID.IsPresent { return ($CurrentUserConfigurations.StrictKernelPolicyGUID ?? $null) }
            $StrictKernelNoFlightRootsPolicyGUID.IsPresent { return ($CurrentUserConfigurations.StrictKernelNoFlightRootsPolicyGUID ?? $null) }
            $CertPath.IsPresent { return ($CurrentUserConfigurations.CertificatePath ?? $null) }
            $LastUpdateCheck.IsPresent { return ($CurrentUserConfigurations.LastUpdateCheck ?? $null) }
            $StrictKernelModePolicyTimeOfDeployment.IsPresent { return ($CurrentUserConfigurations.StrictKernelModePolicyTimeOfDeployment ?? $null) }
            Default {
                # If no parameter is present
                Return $CurrentUserConfigurations
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
    Shows the path to an Unsigned WDAC xml policy
.PARAMETER CertCN
    Shows the certificate common name
.PARAMETER SignToolPath
    Shows the path to the SignTool.exe
.PARAMETER CertPath
    Shows the path to a .cer certificate file
.PARAMETER Open
    Opens the User Configuration file with the default app assigned to open Json files
.PARAMETER StrictKernelPolicyGUID
    Shows the GUID of the Strict Kernel mode policy
.PARAMETER StrictKernelNoFlightRootsPolicyGUID
    Shows the GUID of the Strict Kernel no Flights root mode policy
.PARAMETER LastUpdateCheck
    Shows the date of the last update check
.PARAMETER StrictKernelModePolicyTimeOfDeployment
    Shows the date of the last Strict Kernel mode policy deployment
.PARAMETER Verbose
    Shows verbose messages
.INPUTS
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.Object[]
    System.DateTime
    System.String
    System.Guid
#>
}
