Function Edit-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'AllowNewApps',
        PositionalBinding = $false
    )]
    Param(
        [Alias('A')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')][switch]$AllowNewApps,
        [Alias('M')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies')][switch]$MergeSupplementalPolicies,
        [Alias('U')]
        [Parameter(Mandatory = $false, ParameterSetName = 'UpdateBasePolicy')][switch]$UpdateBasePolicy,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AllowNewApps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFileMultiSelectPicker])]
        [ValidateScript({ [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) })]
        [Parameter(Mandatory = $true, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')][switch]$BoostedSecurity,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [ValidateScript({
                if ([WDACConfig.PolicyFileSigningStatusDetection]::Check($_) -eq [WDACConfig.PolicyFileSigningStatusDetection+SigningStatus]::Signed) {
                    Throw 'The currently selected policy xml file is Signed'
                }
                if (![WDACConfig.CheckPolicyDeploymentStatus]::IsDeployed($_)) {
                    throw 'The currently selected policy xml file is not deployed.'
                }
                # Send $true to set it as valid if no errors were thrown before
                $true
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$PolicyPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies')]
        [switch]$KeepOldSupplementalPolicies,

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [switch]$NoScript,

        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [switch]$NoUserPEs,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String]$SpecificFileNameLevel,

        [ValidateRange(1024KB, 18014398509481983KB)]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.UInt64]$LogSize,

        [ArgumentCompleter({
                foreach ($Item in [WDACConfig.BasePolicyNamez]::New().GetValidValues()) {
                    if ($Item.Contains(' ')) {
                        "'$Item'"
                    }
                }
            })]
        [Parameter(Mandatory = $true, ParameterSetName = 'UpdateBasePolicy')][System.String[]]$CurrentBasePolicyName,

        [ValidateSet('DefaultWindows', 'AllowMicrosoft', 'SignedAndReputable')]
        [Parameter(Mandatory = $true, ParameterSetName = 'UpdateBasePolicy')][System.String]$NewBasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = 'UpdateBasePolicy')][switch]$RequireEVSigners
    )
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        [WDACConfig.Logger]::Write('Importing the required sub-modules')
        $ModulesToImport = @(
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Receive-CodeIntegrityLogs.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Set-LogPropertiesVisibility.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Select-LogProperties.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Test-KernelProtectedFiles.psm1"
        )
        $ModulesToImport += ([WDACConfig.FileUtility]::GetFilesFast("$([WDACConfig.GlobalVars]::ModuleRootPath)\XMLOps", $null, '.psm1')).FullName
        Import-Module -FullyQualifiedName $ModulesToImport -Force

        Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement

        if ([WDACConfig.GlobalVars]::ConfigCIBootstrap -eq $false) {
            Invoke-MockConfigCIBootstrap
            [WDACConfig.GlobalVars]::ConfigCIBootstrap = $true
        }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('Edit-WDACConfig')

        #Region User-Configurations-Processing-Validation
        # make sure the ParameterSet being used has PolicyPath parameter - Then enforces "mandatory" attribute for the parameter
        if ($PSCmdlet.ParameterSetName -in 'AllowNewApps', 'MergeSupplementalPolicies') {
            # If PolicyPath was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
            if (!$PolicyPath) {
                if ([System.IO.File]::Exists(([WDACConfig.UserConfiguration]::Get().UnsignedPolicyPath))) {
                    $PolicyPath = [WDACConfig.UserConfiguration]::Get().UnsignedPolicyPath
                }
                else {
                    throw 'PolicyPath parameter cannot be empty and no valid user configuration was found for UnsignedPolicyPath.'
                }
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # Validate the Level and Fallbacks parameters when using the Boosted Security mode
        if ($BoostedSecurity) {
            $AllowedLevelsForBoostedSecurityMode = [System.Collections.Generic.HashSet[System.String]]@('Hash', 'FileName', 'SignedVersion', 'FilePublisher', 'WHQLFilePublisher')

            if (-NOT ($AllowedLevelsForBoostedSecurityMode.Contains($Level))) {
                Throw 'When using the Boosted Security mode, the Level parameter can only contain the following values: Hash, FileName, SignedVersion, FilePublisher, WHQLFilePublisher'
            }

            foreach ($Fallback in $Fallbacks) {
                if (-NOT ($AllowedLevelsForBoostedSecurityMode.Contains($Fallback))) {
                    Throw 'When using the Boosted Security mode, the Fallbacks parameter can only contain the following values: Hash, FileName, SignedVersion, FilePublisher, WHQLFilePublisher'
                }
            }
        }
    }

    process {

        try {

            if ($AllowNewApps) {
                Write-Host -ForegroundColor Green -Object "This parameter's job has been completely added to the new AppControl Manager app. It offers a complete graphical user interface (GUI) for easy usage. Please refer to this GitHub page to see how to install and use it:`nhttps://github.com/HotCakeX/Harden-Windows-Security/wiki/AppControl-Manager"
            }

            if ($MergeSupplementalPolicies) {

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 5
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Verifying the input files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Getting the IDs of the currently deployed policies on the system')
                $DeployedPoliciesIDs = [System.Collections.Generic.HashSet[System.String]]::new([System.StringComparer]::InvariantCultureIgnoreCase)
                foreach ($Item in [WDACConfig.CiToolHelper]::GetPolicies($true, $true, $true).policyID) {
                    [System.Void]$DeployedPoliciesIDs.Add("{$Item}")
                }

                #Region Input-policy-verification
                [WDACConfig.Logger]::Write('Verifying the input policy files')
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                    [WDACConfig.Logger]::Write("Getting policy ID and type of: $SuppPolicyPath")
                    [System.Xml.XmlDocument]$Supplementalxml = Get-Content -Path $SuppPolicyPath
                    [System.String]$SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID
                    [System.String]$SupplementalPolicyType = $Supplementalxml.SiPolicy.PolicyType

                    # Check the type of the user selected Supplemental policy XML files to make sure they are indeed Supplemental policies
                    [WDACConfig.Logger]::Write('Checking the type of the policy')
                    if ($SupplementalPolicyType -ne 'Supplemental Policy') {
                        Throw "The Selected XML file with GUID $SupplementalPolicyID isn't a Supplemental Policy."
                    }

                    # Check to make sure the user selected Supplemental policy XML files are deployed on the system
                    [WDACConfig.Logger]::Write('Checking the deployment status of the policy')
                    if (!$DeployedPoliciesIDs.Contains($SupplementalPolicyID)) {
                        Throw "The Selected Supplemental XML file with GUID $SupplementalPolicyID isn't deployed on the system."
                    }
                }
                #Endregion Input-policy-verification

                [WDACConfig.Logger]::Write('Backing up any possible Macros in the Supplemental policies')
                $MacrosBackup = [WDACConfig.Macros]::Backup($SuppPolicyPaths)

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [System.IO.FileInfo]$FinalSupplementalPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

                [WDACConfig.Logger]::Write('Merging the Supplemental policies into a single policy file')
                $null = Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath $FinalSupplementalPath

                # Remove the deployed Supplemental policies that user selected from the system, because we're going to deploy the new merged policy that contains all of them
                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Removing old policies from the system' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Removing the deployed Supplemental policies that user selected from the system')
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                    # Get the policy ID of the currently selected Supplemental policy
                    [System.Xml.XmlDocument]$Supplementalxml = Get-Content -Path $SuppPolicyPath
                    [System.String]$SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID

                    [WDACConfig.Logger]::Write("Removing policy with ID: $SupplementalPolicyID")
                    [WDACConfig.CiToolHelper]::RemovePolicy($SupplementalPolicyID)
                }

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Configuring the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Preparing the final merged Supplemental policy for deployment')
                [WDACConfig.Logger]::Write('Converting the policy to a Supplemental policy type and resetting its ID')
                [System.String]$SuppPolicyID = [WDACConfig.SetCiPolicyInfo]::Set($FinalSupplementalPath, $true, "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')", $null, $PolicyPath)

                [WDACConfig.UpdateHvciOptions]::Update($FinalSupplementalPath)

                [WDACConfig.Macros]::Restore($FinalSupplementalPath, $MacrosBackup)

                [WDACConfig.Logger]::Write('Converting the Supplemental policy to a CIP file')
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip")

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip"))

                Write-ColorfulTextWDACConfig -Color TeaGreen -InputText "The Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones."

                # Copying the final Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $FinalSupplementalPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                # remove the old policy files at the end after ensuring the operation was successful
                if (!$KeepOldSupplementalPolicies) {
                    [WDACConfig.Logger]::Write('Removing the old policy files')
                    Remove-Item -Path $SuppPolicyPaths -Force
                }
            }

            if ($UpdateBasePolicy) {

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 5
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Getting the block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Getting the Use Mode Block Rules')
                New-WDACConfig -GetUserModeBlockRules -Deploy

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Determining the policy type' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [System.IO.FileInfo]$BasePolicyPath = Join-Path -Path $StagingArea -ChildPath 'BasePolicy.xml'

                [WDACConfig.Logger]::Write('Determining the type of the new base policy')

                [System.String]$Name = $null

                switch ($NewBasePolicyType) {
                    'AllowMicrosoft' {
                        $Name = 'AllowMicrosoft'

                        [WDACConfig.Logger]::Write("The new base policy type is $Name")

                        [WDACConfig.Logger]::Write('Copying the AllowMicrosoft.xml template policy file to the Staging Area')
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $BasePolicyPath -Force

                        [WDACConfig.Logger]::Write('Setting the policy name')
                        $null = [WDACConfig.SetCiPolicyInfo]::Set($BasePolicyPath, $null, "$Name - $(Get-Date -Format 'MM-dd-yyyy')", $null, $null)

                        [WDACConfig.CiRuleOptions]::Set($BasePolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $RequireEVSigners, $null, $null, $null)
                    }
                    'SignedAndReputable' {
                        $Name = 'SignedAndReputable'

                        [WDACConfig.Logger]::Write("The new base policy type is $Name")

                        [WDACConfig.Logger]::Write('Copying the AllowMicrosoft.xml template policy file to the Staging Area')
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $BasePolicyPath -Force

                        [WDACConfig.Logger]::Write('Setting the policy name')
                        $null = [WDACConfig.SetCiPolicyInfo]::Set($BasePolicyPath, $null, "$Name - $(Get-Date -Format 'MM-dd-yyyy')", $null, $null)

                        [WDACConfig.CiRuleOptions]::Set($BasePolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::BaseISG, $null, $null, $null, $null, $null, $RequireEVSigners, $null, $null, $null)

                        [WDACConfig.ConfigureISGServices]::Configure()
                    }
                    'DefaultWindows' {
                        $Name = 'DefaultWindows'

                        [WDACConfig.Logger]::Write("The new base policy type is $Name")

                        [WDACConfig.Logger]::Write('Copying the DefaultWindows.xml template policy file to the Staging Area')
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination $BasePolicyPath -Force

                        if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                            [WDACConfig.Logger]::Write('Scanning the PowerShell core directory ')

                            Write-ColorfulTextWDACConfig -Color HotPink -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'

                            New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                            [WDACConfig.Logger]::Write('Merging the DefaultWindows.xml and AllowPowerShell.xml into a single policy file')
                            $null = Merge-CIPolicy -PolicyPaths $BasePolicyPath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml') -OutputFilePath $BasePolicyPath
                        }

                        [WDACConfig.Logger]::Write('Setting the policy name')
                        $null = [WDACConfig.SetCiPolicyInfo]::Set($BasePolicyPath, $null, "$Name - $(Get-Date -Format 'MM-dd-yyyy')", $null, $null)

                        [WDACConfig.CiRuleOptions]::Set($BasePolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Base, $null, $null, $null, $null, $null, $RequireEVSigners, $null, $null, $null)
                    }
                }

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Configuring the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.Logger]::Write('Getting the policy ID of the currently deployed base policy based on the policy name that user selected')
                # In case there are multiple policies with the same name, the first one will be used
                [WDACConfig.CiPolicyInfo]$CurrentlyDeployedPolicy = [WDACConfig.CiToolHelper]::GetPolicies($false, $true, $true) | Where-Object -FilterScript { $_.Friendlyname -eq $CurrentBasePolicyName } | Select-Object -First 1

                [System.String]$CurrentID = $CurrentlyDeployedPolicy.BasePolicyID
                [System.Version]$CurrentVersion = $CurrentlyDeployedPolicy.Version

                # Increment the version and use it to deploy the updated policy
                [System.Version]$VersionToDeploy = [WDACConfig.VersionIncrementer]::AddVersion($CurrentVersion)

                [WDACConfig.Logger]::Write("This is the current ID of deployed base policy that is going to be used in the new base policy: $CurrentID")

                [WDACConfig.Logger]::Write('Setting the policy ID and Base policy ID to the current base policy ID in the generated XML file')
                [WDACConfig.PolicyEditor]::EditGUIDs($CurrentID, $BasePolicyPath)

                [WDACConfig.SetCiPolicyInfo]::Set($BasePolicyPath, ([version]$VersionToDeploy))

                [WDACConfig.Logger]::Write('Converting the base policy to a CIP file')
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $BasePolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$CurrentID.cip")

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Deploying the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [WDACConfig.CiToolHelper]::UpdatePolicy($CIPPath)

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Cleaning up' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Keep the new base policy XML file that was just deployed for user to keep it
                # Defining a hashtable that contains the policy names and their corresponding XML file names + paths
                [System.Collections.Hashtable]$PolicyFiles = @{
                    'AllowMicrosoft'     = (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'AllowMicrosoft.xml')
                    'SignedAndReputable' = (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'SignedAndReputable.xml')
                    'DefaultWindows'     = (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'DefaultWindows.xml')
                }

                [WDACConfig.Logger]::Write('Renaming the base policy XML file to match the new base policy type')
                # Copy the new base policy to the user's config directory since Staging Area is a temporary location
                Move-Item -Path $BasePolicyPath -Destination $PolicyFiles[$NewBasePolicyType] -Force

                Write-ColorfulTextWDACConfig -Color Pink -InputText "Base Policy has been successfully updated to $NewBasePolicyType"

                if ([WDACConfig.UserConfiguration]::Get().UnsignedPolicyPath) {
                    [WDACConfig.Logger]::Write('Replacing the old unsigned policy path in User Configurations with the new one')
                    $null = [WDACConfig.UserConfiguration]::Set($null, $PolicyFiles[$NewBasePolicyType], $null, $null, $null, $null, $null, $null, $null, $null)
                }
            }
        }
        catch {
            throw $_
        }
        Finally {
            foreach ($ID in 10..12) {
                Write-Progress -Id $ID -Activity 'Complete.' -Completed
            }
            if (![WDACConfig.GlobalVars]::DebugPreference) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    This cmdlet offers various options for managing the deployed Application Control (WDAC) policies.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig
.PARAMETER AllowNewApps
    While an unsigned WDAC policy is already deployed on the system, rebootlessly turn on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked.
    This parameter also scans the Code Integrity and AppLocker logs during the audit mode phase to detect the audited files.
    It has the ability to detect and create rules for kernel-protected files, such as the main executables of the Xbox games.
.PARAMETER MergeSupplementalPolicies
    Merges multiple deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one.
.PARAMETER UpdateBasePolicy
    It can rebootlessly change the type of the deployed base policy.
.PARAMETER Level
    The level that determines how the selected folder will be scanned.
    The default value for it is WHQLFilePublisher.
.PARAMETER Fallbacks
    The fallback level(s) that determine how the selected folder will be scanned.
    The default value for it is (FilePublisher, Hash).
.PARAMETER LogSize
    The log size to set for Code Integrity/Operational event logs
    The accepted values are between 1024 KB and 18014398509481983 KB
    The max range is the maximum allowed log size by Windows Event viewer
.PARAMETER SuppPolicyName
    The name of the Supplemental policy that will be created
.PARAMETER PolicyPath
    The path to the base policy XML file that will be used
.PARAMETER SuppPolicyPaths
    The path(s) to the Supplemental policy XML file(s) that will be used in the merge operation.
.PARAMETER KeepOldSupplementalPolicies
    Keep the old Supplemental policies that are going to be merged into a single policy
.PARAMETER NoScript
    If specified, scripts will not be scanned
.PARAMETER BoostedSecurity
    If specified, reinforced rules will be created that offer pseudo-sandbox capabilities
.PARAMETER NoUserPEs
    If specified, user mode binaries will not be scanned
.PARAMETER SpecificFileNameLevel
    The more specific level that determines how the selected file will be scanned.
.PARAMETER CurrentBasePolicyName
    The name of the currently deployed base policy that will be used
.PARAMETER NewBasePolicyType
    The type of the new base policy that will be used
.PARAMETER RequireEVSigners
    If specified, the EV Signers rule option will be added to the base policy
.PARAMETER Debug
    If specified, the extra files created during module operation will not be deleted
.INPUTS
    System.UInt64
    System.String[]
    System.String
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}