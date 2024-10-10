Function New-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'All',
        PositionalBinding = $false
    )]
    [OutputType([System.String])]
    Param(
        [Alias('Type')]
        [ValidateSet('DefaultWindows', 'AllowMicrosoft', 'SignedAndReputable')]
        [Parameter(Mandatory = $false, ParameterSetName = 'PolicyType')][System.String]$PolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = 'GetUserModeBlockRules')][System.Management.Automation.SwitchParameter]$GetUserModeBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'GetDriverBlockRules')][System.Management.Automation.SwitchParameter]$GetDriverBlockRules,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$Deploy,

        [Parameter(Mandatory = $false, ParameterSetName = 'GetDriverBlockRules')][System.Management.Automation.SwitchParameter]$AutoUpdate,

        [Parameter(Mandatory = $false, ParameterSetName = 'PolicyType')]
        [System.Management.Automation.SwitchParameter]$Audit,

        [Parameter(Mandatory = $false, ParameterSetName = 'PolicyType')]
        [System.Management.Automation.SwitchParameter]$TestMode,

        [Parameter(Mandatory = $false, ParameterSetName = 'PolicyType')]
        [System.Management.Automation.SwitchParameter]$RequireEVSigners,

        [Parameter(Mandatory = $false, ParameterSetName = 'PolicyType')]
        [System.Management.Automation.SwitchParameter]$EnableScriptEnforcement,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    DynamicParam {

        # Create a new dynamic parameter dictionary
        $ParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

        # Create a dynamic parameter for -LogSize with ValidateRange if -Audit switch is used
        if ($PSBoundParameters['Audit']) {

            # Create a parameter attribute collection
            $LogSize_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            # Create a mandatory attribute and add it to the collection
            [System.Management.Automation.ParameterAttribute]$LogSize_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $LogSize_MandatoryAttrib.Mandatory = $false
            $LogSize_AttributesCollection.Add($LogSize_MandatoryAttrib)

            # Create a Validate Range attribute and add it to the attributes collection
            $LogSize_ValidateRangeAttrib = [System.Management.Automation.ValidateRangeAttribute]::new(1024KB, 18014398509481983KB)
            $LogSize_AttributesCollection.Add($LogSize_ValidateRangeAttrib)

            # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
            [System.Management.Automation.RuntimeDefinedParameter]$LogSize = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('LogSize', [System.UInt64], $LogSize_AttributesCollection)

            # Add the dynamic parameter object to the dictionary
            $ParamDictionary.Add('LogSize', $LogSize)
        }
        return $ParamDictionary
    }
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        if ([WDACConfig.GlobalVars]::ConfigCIBootstrap -eq $false) {
            Invoke-MockConfigCIBootstrap
            [WDACConfig.GlobalVars]::ConfigCIBootstrap = $true
        }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('New-WDACConfig')

        # Define the variables in the function scope for the dynamic parameters
        New-Variable -Name 'LogSize' -Value $PSBoundParameters['LogSize'] -Force

        Function Build-DefaultWindows {
            <#
            .SYNOPSIS
                Creates a base policy based off the DefaultWindows template.
            .INPUTS
                None
            .OUTPUTS
                System.String
            #>
            if ($Audit) { [WDACConfig.EventLogUtility]::SetLogSize($LogSize ?? 0) }
            [System.String]$Name = $Audit ? 'DefaultWindowsAudit' : 'DefaultWindows'

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 4 : 3
            [System.UInt16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Getting the recommended block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            [WDACConfig.BasePolicyCreator]::GetBlockRules($StagingArea, $Deploy, $false)

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath "$Name.xml"

            [WDACConfig.Logger]::Write('Copying the DefaultWindows_Enforced.xml from Windows directory to the Staging Area')
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination $FinalPolicyPath -Force

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Determining whether to include PowerShell core' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Scan PowerShell core directory (if installed using MSI only, because Microsoft Store installed version doesn't need to be allowed manually) and allow its files in the Default Windows base policy so that module can still be used once it's been deployed
            if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                Write-ColorfulTextWDACConfig -Color Lavender -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                [WDACConfig.Logger]::Write("Merging the policy files to create the final $Name.xml policy")
                $null = Merge-CIPolicy -PolicyPaths $FinalPolicyPath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml') -OutputFilePath $FinalPolicyPath
            }

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Configuring policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            [WDACConfig.Logger]::Write('Resetting the policy ID and assigning policy name')
            $null = [WDACConfig.SetCiPolicyInfo]::Set($FinalPolicyPath, $true, "$Name - $(Get-Date -Format 'MM-dd-yyyy')", $null, $null)

            [WDACConfig.SetCiPolicyInfo]::Set($FinalPolicyPath, ([version]'1.0.0.0'))

            [WDACConfig.CiRuleOptions]::Set($FinalPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $Audit, $null, $RequireEVSigners, $EnableScriptEnforcement, $TestMode, $null)

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 7 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Converting the policy file to .CIP binary')
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                [WDACConfig.CiToolHelper]::UpdatePolicy($CIPPath)
            }

            # Copy the result to the User Config directory at the end
            Copy-Item -Path $FinalPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            Write-FinalOutput -Paths $FinalPolicyPath

            Write-Progress -Id 7 -Activity 'Complete.' -Completed
        }

        if (-NOT $SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }
    }

    process {
        Try {
            Switch ($PSCmdlet.ParameterSetName) {
                'PolicyType' {
                    Switch ($PSBoundParameters['PolicyType']) {
                        'DefaultWindows' { Build-DefaultWindows ; break }
                        'AllowMicrosoft' { [WDACConfig.BasePolicyCreator]::BuildAllowMSFT($StagingArea, $Audit, $LogSize, $Deploy, $RequireEVSigners, $EnableScriptEnforcement, $TestMode, $false) ; break }
                        'SignedAndReputable' { [WDACConfig.BasePolicyCreator]::BuildSignedAndReputable($StagingArea, $Audit, $LogSize, $Deploy, $RequireEVSigners, $EnableScriptEnforcement, $TestMode, $false) ; break }
                    }
                }
                'GetUserModeBlockRules' { [WDACConfig.BasePolicyCreator]::GetBlockRules($StagingArea, $Deploy, $false) ; break }
                'GetDriverBlockRules' {
                    if ($AutoUpdate) {
                        [WDACConfig.BasePolicyCreator]::SetAutoUpdateDriverBlockRules(); break
                    }
                    if ($Deploy) {
                        [WDACConfig.BasePolicyCreator]::DeployDriversBlockRules($StagingArea); break
                    }
                    else {
                        [WDACConfig.BasePolicyCreator]::GetDriversBlockRules($StagingArea); break
                    }
                    break
                }
                default { Write-Warning -Message 'None of the main parameters were selected.'; break }
            }
        }
        catch {
            throw $_
        }
        Finally {
            if (![WDACConfig.GlobalVars]::DebugPreference) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    Automate a lot of tasks related to App Control for Business
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig
.PARAMETER PolicyType
    The type of policy to create: DefaultWindows, AllowMicrosoft, SignedAndReputable
.PARAMETER GetUserModeBlockRules
    Gets the latest Microsoft Recommended User Mode Block rules
.PARAMETER GetDriverBlockRules
    Gets the latest Microsoft Recommended Driver Block rules
.PARAMETER AutoUpdate
    Creates a scheduled task that will keep the Microsoft Recommended Driver Block rules up to date by downloading and applying
    the latest block list every 7 days on the system.
.PARAMETER EnableScriptEnforcement
    Enable script enforcement for the policy
.PARAMETER Deploy
    Deploys the policy that is being created
.PARAMETER TestMode
    Indicates that the created/deployed policy will have Enabled:Boot Audit on Failure and Enabled:Advanced Boot Options Menu policy rule options
.PARAMETER RequireEVSigners
    Indicates that the created/deployed policy will have Require EV Signers policy rule option.
.PARAMETER LogSize
    Specifies the log size for Microsoft-Windows-CodeIntegrity/Operational events. The values must be in the form of <Digit + Data measurement unit>. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.
    The maximum range is the maximum allowed log size by Windows Event viewer.
    The parameter is only available when -Audit is used.
.PARAMETER Audit
    Indicates that the created/deployed policy will have Enabled:Audit Mode policy rule option and will generate audit logs instead of blocking files.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.PARAMETER Verbose
    Displays detailed information about the operation performed by the command
.INPUTS
    System.UInt64
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}
