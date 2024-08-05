Function Get-CIPolicySetting {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true)][System.String]$Provider,
        [Parameter(Mandatory = $true)][System.String]$Key,
        [Parameter(Mandatory = $true)][System.String]$ValueName,
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Update-Self.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }
    }
    Process {
        try {
            # Create UNICODE_STRING structures
            $ProviderUS = [WDACConfig.WldpQuerySecurityPolicyWrapper]::InitUnicodeString($Provider)
            $KeyUS = [WDACConfig.WldpQuerySecurityPolicyWrapper]::InitUnicodeString($Key)
            $ValueNameUS = [WDACConfig.WldpQuerySecurityPolicyWrapper]::InitUnicodeString($ValueName)

            # Prepare output variables
            $ValueType = [WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE]::WldpNone
            $ValueSize = [System.UInt64]1024
            $Value = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ValueSize)

            $Result = [WDACConfig.WldpQuerySecurityPolicyWrapper]::WldpQuerySecurityPolicy([ref]$ProviderUS, [ref]$KeyUS, [ref]$ValueNameUS, [ref]$ValueType, $Value, [ref]$ValueSize)

            $DecodedValue = $null

            if ($Result -eq 0) {
                switch ($ValueType) {
                    'WldpBoolean' {
                        $DecodedValue = [System.Runtime.InteropServices.Marshal]::ReadByte($Value) -ne 0
                    }
                    'WldpString' {
                        $DecodedValue = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Value)
                    }
                    'WldpInteger' {
                        $DecodedValue = [System.Runtime.InteropServices.Marshal]::ReadInt32($Value)
                    }
                }
            }

            Return [PSCustomObject]@{
                Value      = $DecodedValue
                ValueType  = $ValueType
                ValueSize  = $ValueSize
                Status     = $Result -eq 0 ? $true : $false
                StatusCode = $Result
            }
        }
        catch {
            throw $_
        }
        finally {
            # Clean up
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProviderUS.Buffer)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($KeyUS.Buffer)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ValueNameUS.Buffer)
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Value)
        }
    }
    <#
    .SYNOPSIS
        Gets the secure settings value from the deployed CI policies.
        If there is a policy with the same provider, key and value then it returns the following details:

        Value = The actual value of the string
        ValueType = The type of setting: WldpString, WldpInteger or WldpBoolean
        ValueSize = the size of the returned value
        Status = True/False depending on whether the setting exists on the system or not
        StatusCode = 0 if the value exists on the system, non-zero if it doesn't.
    .DESCRIPTION
        Please use the following resources for more information

        https://learn.microsoft.com/en-us/powershell/module/configci/set-cipolicysetting
        https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/understanding-wdac-policy-settings
    .LINK
        https://github.com/HotCakeX/Harden-Windows-Security/wiki/Get-CIPolicySetting
    .INPUTS
        System.String
    .OUTPUTS
        PSCustomObject
    .PARAMETER Provider
        The provider of the secure setting
    .PARAMETER Key
        The key of the secure setting
    .PARAMETER ValueName
        The name of the secure setting
    .PARAMETER SkipVersionCheck
        If this switch is present, the cmdlet will skip the version check
    .EXAMPLE
        Creating the secure settings in a Code Integrity policy

        Set-CIPolicySetting -FilePath 'Policy.xml' -Provider 'WDACConfig' -ValueType 'Boolean' -Value '1' -ValueName 'IsUserModePolicy' -Key '{4a981f19-1f7f-4167-b4a6-915765e34fd6}'
    .EXAMPLE
        Creating the secure settings in a Code Integrity policy

        Set-CIPolicySetting -FilePath 'Policy.xml' -Provider 'SomeProvider' -ValueType 'String' -Value 'HotCakeX' -ValueName 'Author' -Key '{495e96a3-f6e0-4e7e-bf48-e8b6085b824a}'
    .EXAMPLE
        Creating the secure settings in a Code Integrity policy

        Set-CIPolicySetting -FilePath 'Policy.xml' -Provider 'Provider2' -ValueType 'DWord' -Value '66' -ValueName 'Role' -Key '{741b1fcf-e1ce-49e4-a274-5c367b46b00c}'
    .EXAMPLE
        Using the Get-CIPolicySetting cmdlet to query the secure strings among the deployed policies on the system.

        Get-CIPolicySetting -Provider 'WDACConfig' -Key '{4a981f19-1f7f-4167-b4a6-915765e34fd6}' -ValueName 'IsUserModePolicy'
    .EXAMPLE
        Using the Get-CIPolicySetting cmdlet to query the secure strings among the deployed policies on the system.

        Get-CIPolicySetting -Provider 'SomeProvider' -ValueName 'Author' -Key '{495e96a3-f6e0-4e7e-bf48-e8b6085b824a}'
    .EXAMPLE
        Using the Get-CIPolicySetting cmdlet to query the secure strings among the deployed policies on the system.

        Get-CIPolicySetting -Provider 'Provider2' -ValueName 'Role' -Key '{741b1fcf-e1ce-49e4-a274-5c367b46b00c}'
    .NOTES
        Note-1
        Since these settings are secured by Secure Boot, in order to successfully query these settings, you might need to restart once after deploying the CI Policy on the system.

        Note-2
        DWord value is the same as integer or WldpInteger

        Note-3
        In order to set a Boolean value using the Set-CIPolicySetting cmdlet, you need to use 1 for True or 0 for False, that will create a valid policy XML file that is compliant with the CI Policy Schema.
        #>
}
