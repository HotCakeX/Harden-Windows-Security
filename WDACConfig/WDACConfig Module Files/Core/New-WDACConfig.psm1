Function New-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Get Block Rules',
        PositionalBinding = $false
    )]
    Param(
        # 9 Main parameters - should be used for position 0
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Block Rules')][System.Management.Automation.SwitchParameter]$GetBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Driver Block Rules')][System.Management.Automation.SwitchParameter]$GetDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')][System.Management.Automation.SwitchParameter]$MakeAllowMSFTWithBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Set Auto Update Driver Block Rules')][System.Management.Automation.SwitchParameter]$SetAutoUpdateDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep MSFT Only Audit')][System.Management.Automation.SwitchParameter]$PrepMSFTOnlyAudit,
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep Default Windows Audit')][System.Management.Automation.SwitchParameter]$PrepDefaultWindowsAudit,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')][System.Management.Automation.SwitchParameter]$MakePolicyFromAuditLogs,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')][System.Management.Automation.SwitchParameter]$MakeLightPolicy,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')][System.Management.Automation.SwitchParameter]$MakeDefaultWindowsWithBlockRules,

        [ValidateSet('Allow Microsoft Base', 'Default Windows Base')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String]$BasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep MSFT Only Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep Default Windows Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Driver Block Rules')]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.Management.Automation.SwitchParameter]$IncludeSignTool,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.String]$SignToolPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.Management.Automation.SwitchParameter]$TestMode,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.Management.Automation.SwitchParameter]$RequireEVSigners,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Management.Automation.SwitchParameter]$NoDeletedFiles,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String]$Level = 'FilePublisher',

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String[]]$Fallbacks = 'Hash',

        [ValidateRange(1024KB, 18014398509481983KB)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep MSFT Only Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep Default Windows Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Int64]$LogSize,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-SignTool.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-GlobalRootDrives.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Set-LogSize.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-EmptyPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-RuleRefs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-FileRules.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-BlockRulesMeta.psm1" -Force

        #Region User-Configurations-Processing-Validation
        # If User is creating Default Windows policy and is including SignTool path
        if ($IncludeSignTool -and $MakeDefaultWindowsWithBlockRules) {
            # Get SignToolPath from user parameter or user config file or auto-detect it
            if ($SignToolPath) {
                $SignToolPathFinal = Get-SignTool -SignToolExePathInput $SignToolPath
            } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
            else {
                $SignToolPathFinal = Get-SignTool -SignToolExePathInput (Get-CommonWDACConfig -SignToolPath)
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # argument tab auto-completion and ValidateSet for Fallbacks
        Class Fallbackz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Fallbackz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
                return [System.String[]]$Fallbackz
            }
        }

        # argument tab auto-completion and ValidateSet for level
        Class Levelz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Levelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
                return [System.String[]]$Levelz
            }
        }
        Function Get-DriverBlockRules {
            <#
            .SYNOPSIS
                Gets the latest Microsoft Recommended Driver Block rules and processes them
                Can optionally deploy them
            .INPUTS
                System.Management.Automation.SwitchParameter
            .OUTPUTS
                System.String
            .PARAMETER Deploy
                Indicates that the function will deploy the latest Microsoft recommended drivers block list
            #>
            [CmdletBinding()]
            param (
                [System.Management.Automation.SwitchParameter]$Deploy
            )

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 3
            [System.Int16]$CurrentStep = 0

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Downloading the driver block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Downloading the Microsoft Recommended Driver Block List archive'
                Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile VulnerableDriverBlockList.zip -ProgressAction SilentlyContinue

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Expanding the archive' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Expanding the Block list archive'
                Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath 'VulnerableDriverBlockList' -Force

                Write-Verbose -Message 'Renaming the block list file to SiPolicy.p7b'
                Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName 'SiPolicy.p7b' -Force

                Write-Verbose -Message 'Copying the new block list to the CodeIntegrity folder, replacing any old ones'
                Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination 'C:\Windows\System32\CodeIntegrity' -Force

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Refreshing the system policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Refreshing the system WDAC policies using CiTool.exe'
                &'C:\Windows\System32\CiTool.exe' --refresh -json | Out-Null

                Write-ColorfulText -Color Pink -InputText 'SiPolicy.p7b has been deployed and policies refreshed.'

                Write-Verbose -Message 'Cleaning up'
                Remove-Item -Path .\VulnerableDriverBlockList* -Recurse -Force

                Write-Verbose -Message 'Displaying extra info about the Microsoft recommended Drivers block list'
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
            }
            else {
                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Downloading the driver block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Downloading the latest Microsoft Recommended Driver Block Rules from the official source'
                [System.String]$DriverRules = (Invoke-WebRequest -Uri $MSFTRecommendedDriverBlockRulesURL -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1'

                # Remove the unnecessary rules and elements - not using this one because then during the merge there will be error - The reason is that "<FileRuleRef RuleID="ID_ALLOW_ALL_2" />" is the only FileruleRef in the xml and after removing it, the <SigningScenario> element will be empty
                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Removing the Allow all rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Removing the allow all rules and rule refs from the policy'
                $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_[12]"\sFriendlyName=""\sFileName="\*".*/>', ''
                $DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_1".*/>', ''
                $DriverRules = $DriverRules -replace '<SigningScenario\sValue="12"\sID="ID_SIGNINGSCENARIO_WINDOWS"\sFriendlyName="Auto\sgenerated\spolicy[\S\s]*<\/SigningScenario>', ''

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Creating the XML policy file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Creating XML policy file'
                $DriverRules | Out-File -FilePath 'Microsoft recommended driver block rules TEMP.xml' -Force

                # Remove empty lines from the policy file
                Write-Verbose -Message 'Removing the empty lines from the policy XML file'
                Get-Content -Path 'Microsoft recommended driver block rules TEMP.xml' | Where-Object -FilterScript { $_.trim() -ne '' } | Out-File -FilePath 'Microsoft recommended driver block rules.xml' -Force

                Write-Verbose -Message 'Removing the temp XML file'
                Remove-Item -Path 'Microsoft recommended driver block rules TEMP.xml' -Force

                Write-Verbose -Message 'Removing the Audit mode policy rule option'
                Set-RuleOption -FilePath 'Microsoft recommended driver block rules.xml' -Option 3 -Delete

                Write-Verbose -Message 'Setting the HVCI option to strict'
                Set-HVCIOptions -Strict -FilePath 'Microsoft recommended driver block rules.xml'

                # Display extra info about the Microsoft recommended Drivers block list
                Write-Verbose -Message 'Displaying extra info about the Microsoft recommended Drivers block list'
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK

                # Display the result
                Write-ColorfulText -Color MintGreen -InputText 'PolicyFile = Microsoft recommended driver block rules.xml'
            }
            Write-Progress -Id 1 -Activity 'Complete.' -Completed
        }

        Function Build-AllowMSFTWithBlockRules {
            <#
            .SYNOPSIS
                A helper function that downloads the latest Microsoft recommended block rules
                and merges them with the Allow Microsoft template policy.
                It can also deploy the policy on the system.
            .PARAMETER NoCIP
                Indicates that the created .CIP binary file must be deleted at the end.
                It's usually used when calling this function from other functions that don't need the .CIP output of this function.
            .INPUTS
                System.Management.Automation.SwitchParameter
            .OUTPUTS
                System.String
            #>
            [CmdletBinding()]
            param(
                [System.Management.Automation.SwitchParameter]$NoCIP
            )

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 4
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Getting the recommended block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Getting the latest Microsoft recommended block rules'
            Get-BlockRulesMeta 6> $null

            Write-Verbose -Message 'Copying the AllowMicrosoft.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination 'AllowMicrosoft.xml' -Force

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Merging the block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Merging the AllowMicrosoft.xml with Microsoft Recommended Block rules.xml'
            Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\AllowMicrosoftPlusBlockRules.xml | Out-Null

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and setting a name for AllowMicrosoftPlusBlockRules.xml'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoftPlusBlockRules.xml -PolicyName "Allow Microsoft Plus Block Rules - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting AllowMicrosoftPlusBlockRules.xml policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath .\AllowMicrosoftPlusBlockRules.xml -Version '1.0.0.0'

            Write-Verbose -Message 'Configuring the policy rule options'
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ }
            @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ -Delete }

            if ($TestMode -and $MakeAllowMSFTWithBlockRules) {
                Write-Verbose -Message 'Setting "Boot Audit on Failure" and "Advanced Boot Options Menu" policy rule options for the AllowMicrosoftPlusBlockRules.xml policy because TestMode parameter was used'
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ }
            }
            if ($RequireEVSigners -and $MakeAllowMSFTWithBlockRules) {
                Write-Verbose -Message 'Setting "Required:EV Signers" policy rule option for the AllowMicrosoftPlusBlockRules.xml policy because RequireEVSigners parameter was used'
                Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option 8
            }

            Write-Verbose -Message 'Setting HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath .\AllowMicrosoftPlusBlockRules.xml

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Creating CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Converting the AllowMicrosoftPlusBlockRules.xml policy file to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath .\AllowMicrosoftPlusBlockRules.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

            # Remove the extra files that were created during module operation and are no longer needed
            Write-Verbose -Message 'Removing the extra files that were created during module operation and are no longer needed'
            Remove-Item -Path '.\AllowMicrosoft.xml', 'Microsoft recommended block rules.xml' -Force

            Write-Verbose -Message 'Displaying the output'
            Write-ColorfulText -Color MintGreen -InputText 'PolicyFile = AllowMicrosoftPlusBlockRules.xml'
            Write-ColorfulText -Color MintGreen -InputText "BinaryFile = $PolicyID.cip"

            if ($Deploy -and $MakeAllowMSFTWithBlockRules) {
                Write-Verbose -Message 'Deploying the AllowMicrosoftPlusBlockRules.xml policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                Write-Verbose -Message 'Removing the generated .CIP binary file after deploying it'
                Remove-Item -Path "$PolicyID.cip" -Force
            }

            if ($NoCIP) {
                Write-Verbose -Message 'Removing the generated .CIP binary file because -NoCIP parameter was used'
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            Write-Progress -Id 3 -Activity 'Complete' -Completed
        }

        Function Build-DefaultWindowsWithBlockRules {
            <#
            .SYNOPSIS
                A helper function that downloads the latest Microsoft recommended block rules
                and merges them with the DefaultWindows_Enforced template policy.
                It can also deploy the policy on the system.
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.String
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 6
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Getting the recommended block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Getting the latest Microsoft recommended block rules'
            Get-BlockRulesMeta 6> $null

            Write-Verbose -Message 'Copying the DefaultWindows_Enforced.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination 'DefaultWindows_Enforced.xml' -Force

            # Setting a flag for Scanning the SignTool.exe and merging it with the final base policy
            [System.Boolean]$MergeSignToolPolicy = $false

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Determining whether to include SingTool' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            if ($SignToolPathFinal) {
                # Allowing SignTool to be able to run after Default Windows base policy is deployed in Signed scenario
                Write-ColorfulText -Color TeaGreen -InputText "`nCreating allow rules for SignTool.exe in the DefaultWindows base policy so you can continue using it after deploying the DefaultWindows base policy."

                Write-Verbose -Message 'Creating a new temporary directory in the temp directory'
                New-Item -Path "$UserTempDirectoryPath\TemporarySignToolFile" -ItemType Directory -Force | Out-Null

                Write-Verbose -Message 'Copying the SignTool.exe to the newly created directory in the temp directory'
                Copy-Item -Path $SignToolPathFinal -Destination "$UserTempDirectoryPath\TemporarySignToolFile" -Force

                Write-Verbose -Message 'Scanning the SignTool.exe in the temp directory and generating the SignTool.xml policy'
                New-CIPolicy -ScanPath "$UserTempDirectoryPath\TemporarySignToolFile" -Level FilePublisher -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath .\SignTool.xml

                # Delete the Temporary folder in the TEMP folder
                if (!$Debug) {
                    Write-Verbose -Message 'Debug parameter was not used, removing the files created in the temp directory'
                    Remove-Item -Recurse -Path "$UserTempDirectoryPath\TemporarySignToolFile" -Force
                }

                # Setting the flag to true so that the SignTool.xml file will be merged with the final policy
                $MergeSignToolPolicy = $true
            }

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Determining whether to include PowerShell core' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Scan PowerShell core directory (if installed using MSI only, because Microsoft Store installed version doesn't need to be allowed manually) and allow its files in the Default Windows base policy so that module can still be used once it's been deployed
            if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {

                Write-ColorfulText -Color Lavender -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml

                if ($MergeSignToolPolicy) {
                    Write-Verbose -Message 'Merging the policy files, including SignTool.xml, to create the final DefaultWindowsPlusBlockRules.xml policy'
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, 'Microsoft recommended block rules.xml', .\SignTool.xml -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
                else {
                    Write-Verbose -Message 'Merging the policy files to create the final DefaultWindowsPlusBlockRules.xml policy'
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
            }
            else {
                if ($MergeSignToolPolicy) {
                    Write-Verbose -Message 'Merging the policy files, including SignTool.xml, to create the final DefaultWindowsPlusBlockRules.xml policy'
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, 'Microsoft recommended block rules.xml', .\SignTool.xml -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
                else {
                    Write-Verbose -Message 'Merging the policy files to create the final DefaultWindowsPlusBlockRules.xml policy'
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
            }

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Configuring policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and setting a name for DefaultWindowsPlusBlockRules.xml'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\DefaultWindowsPlusBlockRules.xml -PolicyName "Default Windows Plus Block Rules - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting the version of DefaultWindowsPlusBlockRules.xml policy to 1.0.0.0'
            Set-CIPolicyVersion -FilePath .\DefaultWindowsPlusBlockRules.xml -Version '1.0.0.0'

            Write-Verbose -Message 'Configuring the policy rule options'
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ }
            @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ -Delete }

            if ($TestMode -and $MakeDefaultWindowsWithBlockRules) {
                Write-Verbose -Message 'Setting "Boot Audit on Failure" and "Advanced Boot Options Menu" policy rule options for the DefaultWindowsPlusBlockRules.xml policy because TestMode parameter was used'
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ }
            }

            if ($RequireEVSigners -and $MakeDefaultWindowsWithBlockRules) {
                Write-Verbose -Message 'Setting "Required:EV Signers" policy rule option for the DefaultWindowsPlusBlockRules.xml policy because RequireEVSigners parameter was used'
                Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option 8
            }

            Write-Verbose -Message 'Setting HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath .\DefaultWindowsPlusBlockRules.xml

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Converting the DefaultWindowsPlusBlockRules.xml policy file to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath .\DefaultWindowsPlusBlockRules.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Cleaning up' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Removing the extra files that were created during module operation and are no longer needed'
            Remove-Item -Path .\AllowPowerShell.xml -Force -ErrorAction SilentlyContinue
            Remove-Item -Path '.\DefaultWindows_Enforced.xml', 'Microsoft recommended block rules.xml' -Force

            if ($MergeSignToolPolicy -and !$Debug) {
                Write-Verbose -Message 'Deleting SignTool.xml'
                Remove-Item -Path .\SignTool.xml -Force
            }

            Write-Verbose -Message 'Displaying the output'
            Write-ColorfulText -Color MintGreen -InputText 'PolicyFile = DefaultWindowsPlusBlockRules.xml'
            Write-ColorfulText -Color MintGreen -InputText "BinaryFile = $PolicyID.cip"

            if ($Deploy -and $MakeDefaultWindowsWithBlockRules) {
                Write-Verbose -Message 'Deploying the DefaultWindowsPlusBlockRules.xml policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                Write-Verbose -Message 'Removing the generated .CIP binary file after deploying it'
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            Write-Progress -Id 7 -Activity 'Complete.' -Completed
        }

        Function Deploy-LatestBlockRules {
            <#
            .SYNOPSIS
                A helper function that downloads the latest Microsoft recommended block rules
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.String
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 4
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Downloading the latest block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Downloading the latest Microsoft recommended block rules and creating Microsoft recommended block rules TEMP.xml'
            (Invoke-WebRequest -Uri $MSFTRecommendedBlockRulesURL -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1' | Out-File -FilePath '.\Microsoft recommended block rules TEMP.xml' -Force

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Removing the empty lines' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Removing any empty lines from the Temp policy file and generating the Microsoft recommended block rules.xml'
            Get-Content -Path '.\Microsoft recommended block rules TEMP.xml' | Where-Object -FilterScript { $_.trim() -ne '' } | Out-File -FilePath '.\Microsoft recommended block rules.xml' -Force

            Write-Verbose -Message 'Removing the temp XML file'
            Remove-Item -Path '.\Microsoft recommended block rules TEMP.xml' -Force

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Removing the Audit mode policy rule option'
            Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option 3 -Delete

            Write-Verbose -Message 'Adding the required policy rule options'
            @(0, 2, 6, 11, 12, 16, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option $_ }

            Write-Verbose -Message 'Setting the HVCI option to strict'
            Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.xml'

            Write-Verbose -Message 'Resetting the policy ID and saving it to a variable'
            [System.String]$PolicyID = (Set-CIPolicyIdInfo -FilePath '.\Microsoft recommended block rules.xml' -ResetPolicyID).Substring(11)

            Write-Verbose -Message 'Assigning a name to the policy'
            Set-CIPolicyIdInfo -PolicyName "Microsoft Windows User Mode Policy - Enforced - $(Get-Date -Format 'MM-dd-yyyy')" -FilePath '.\Microsoft recommended block rules.xml'

            Write-Verbose -Message 'Converting the Microsoft recommended block rules.xml policy file to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath '.\Microsoft recommended block rules.xml' -BinaryFilePath "$PolicyID.cip" | Out-Null

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Deploying the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the Microsoft recommended block rules policy'
            &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
            Write-ColorfulText -Color Lavender -InputText 'The Microsoft recommended block rules policy has been deployed in enforced mode.'

            Write-Verbose -Message 'Removing the generated .CIP binary file after deploying it'
            Remove-Item -Path "$PolicyID.cip" -Force

            Write-Progress -Id 0 -Activity 'Policy creation complete.' -Completed
        }

        Function Set-AutoUpdateDriverBlockRules {
            <#
            .SYNOPSIS
                A helper function that creates a scheduled task to keep the Microsoft Recommended Driver Block rules
                In Windows up to date quickly ahead of its official release schedule. It does this by downloading and applying
                The latest block list every 7 days on the system.
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.Void
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 1
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 2 -Activity 'Setting up the Scheduled task' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Get the state of fast weekly Microsoft recommended driver block list update scheduled task
            Write-Verbose -Message 'Getting the state of MSFT Driver Block list update Scheduled task'
            [System.String]$BlockListScheduledTaskState = (Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath '\MSFT Driver Block list update\' -ErrorAction SilentlyContinue).State

            # Create scheduled task for fast weekly Microsoft recommended driver block list update if it doesn't exist or exists but is not Ready/Running
            if (-NOT (($BlockListScheduledTaskState -eq 'Ready' -or $BlockListScheduledTaskState -eq 'Running'))) {

                Write-Verbose -Message "Creating the MSFT Driver Block list update task because its state is neither Running nor Ready, it's $BlockListScheduledTaskState"
                # Get the SID of the SYSTEM account. It is a well-known SID, but still querying it, going to use it to create the scheduled task
                [System.Security.Principal.SecurityIdentifier]$SYSTEMSID = New-Object -TypeName System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)

                # Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
                [Microsoft.Management.Infrastructure.CimInstance]$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                    -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit 1};Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "$env:SystemDrive\Windows\System32\CodeIntegrity" -Force;citool --refresh -json;Remove-Item -Path .\VulnerableDriverBlockList -Recurse -Force;Remove-Item -Path .\VulnerableDriverBlockList.zip -Force; exit 0;}"'

                # Create a scheduled task principal and assign the SYSTEM account's SID to it so that the task will run under its context
                [Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $($SYSTEMSID.Value) -RunLevel Highest

                # Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
                [Microsoft.Management.Infrastructure.CimInstance]$Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)

                # Register the scheduled task. If the task's state is disabled, it will be overwritten with a new task that is enabled
                Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update' -Force

                # Define advanced settings for the scheduled task
                [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8' -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 4 -RestartInterval (New-TimeSpan -Hours 6) -RunOnlyIfNetworkAvailable

                # Add the advanced settings we defined above to the scheduled task
                Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings
            }

            Write-Verbose -Message 'Displaying extra info about the Microsoft recommended Drivers block list'
            Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK

            Write-Progress -Id 2 -Activity 'complete.' -Completed
        }

        Function Build-MSFTOnlyAudit {
            <#
            .SYNOPSIS
                A helper function that creates a WDAC policy based on AllowMicrosoft template policy.
                It has audit policy rule option.
                It can also call the Set-LogSize function to modify the size of Code Integrity Operational event log
                It uses the $LogSize variable available in the New-WDACConfig's scope to do that.
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.Void
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 3
            [System.Int16]$CurrentStep = 0

            if ($PrepMSFTOnlyAudit -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            $CurrentStep++
            Write-Progress -Id 5 -Activity 'Creating the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Copying AllowMicrosoft.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination .\AllowMicrosoft.xml -Force

            Write-Verbose -Message 'Enabling Audit mode and disabling script enforcement'
            3, 11 | ForEach-Object -Process { Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option $_ }

            $CurrentStep++
            Write-Progress -Id 5 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the Policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Assigning "PrepMSFTOnlyAudit" as the policy name'
            Set-CIPolicyIdInfo -PolicyName 'PrepMSFTOnlyAudit' -FilePath .\AllowMicrosoft.xml

            $CurrentStep++
            Write-Progress -Id 5 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Converting AllowMicrosoft.xml to .CIP Binary'
            ConvertFrom-CIPolicy -XmlFilePath .\AllowMicrosoft.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

            if ($Deploy) {
                Write-Verbose -Message 'Deploying the AllowMicrosoft.xml policy on the system'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
                Write-ColorfulText -Color HotPink -InputText 'The default AllowMicrosoft policy has been deployed in Audit mode. No reboot required.'
                Remove-Item -Path 'AllowMicrosoft.xml', "$PolicyID.cip" -Force
            }
            else {
                Write-ColorfulText -Color HotPink -InputText 'The default AllowMicrosoft policy has been created in Audit mode and is ready for deployment.'
            }
            Write-Progress -Id 5 -Activity 'complete.' -Completed
        }

        Function Build-DefaultWindowsAudit {
            <#
            .SYNOPSIS
                A helper function that creates a WDAC policy based on DefaultWindows template policy.
                It has audit policy rule option.
                It can also call the Set-LogSize function to modify the size of Code Integrity Operational event log
                It uses the $LogSize variable available in the New-WDACConfig's scope to do that.
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.Void
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 4
            [System.Int16]$CurrentStep = 0

            if ($PrepDefaultWindowsAudit -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            $CurrentStep++
            Write-Progress -Id 8 -Activity 'Fetching the policy template' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Copying DefaultWindows_Audit.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml' -Destination .\DefaultWindows_Audit.xml -Force

            $CurrentStep++
            Write-Progress -Id 8 -Activity 'Determining whether to include PowerShell core' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Making Sure neither PowerShell core (Installed using MSI because Microsoft Store installed version is automatically allowed) nor WDACConfig module files are added to the Supplemental policy created by -MakePolicyFromAuditLogs parameter
            # by adding them first to the deployed Default Windows policy in Audit mode. Because WDACConfig module files don't need to be allowed to run since they are *.ps1 and .*psm1 files
            # And PowerShell core files will be added to the DefaultWindows Base policy anyway
            if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {

                Write-Verbose -Message 'Scanning PowerShell core directory and creating a policy file'
                New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml

                Write-Verbose -Message 'Scanning WDACConfig module directory and creating a policy file'
                New-CIPolicy -ScanPath "$ModuleRootPath" -Level hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\WDACConfigModule.xml

                Write-Verbose -Message 'Merging the policy files for PowerShell core and WDACConfig module with the DefaultWindows_Audit.xml policy file'
                Merge-CIPolicy -PolicyPaths .\DefaultWindows_Audit.xml, .\AllowPowerShell.xml, .\WDACConfigModule.xml -OutputFilePath .\DefaultWindows_Audit_temp.xml | Out-Null

                Write-Verbose -Message 'removing DefaultWindows_Audit.xml policy'
                Remove-Item -Path DefaultWindows_Audit.xml -Force

                Write-Verbose -Message 'Renaming DefaultWindows_Audit_temp.xml to DefaultWindows_Audit.xml'
                Rename-Item -Path .\DefaultWindows_Audit_temp.xml -NewName 'DefaultWindows_Audit.xml' -Force

                Write-Verbose -Message 'Removing AllowPowerShell.xml and WDACConfigModule.xml policies'
                Remove-Item -Path 'WDACConfigModule.xml', 'AllowPowerShell.xml' -Force
            }

            $CurrentStep++
            Write-Progress -Id 8 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Enabling Audit mode and disabling script enforcement'
            3, 11 | ForEach-Object -Process { Set-RuleOption -FilePath .\DefaultWindows_Audit.xml -Option $_ }

            Write-Verbose -Message 'Resetting the Policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\DefaultWindows_Audit.xml -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Assigning "PrepDefaultWindowsAudit" as the policy name'
            Set-CIPolicyIdInfo -PolicyName 'PrepDefaultWindows' -FilePath .\DefaultWindows_Audit.xml

            $CurrentStep++
            Write-Progress -Id 8 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Converting DefaultWindows_Audit.xml to .CIP Binary'
            ConvertFrom-CIPolicy -XmlFilePath .\DefaultWindows_Audit.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

            if ($Deploy) {
                Write-Verbose -Message 'Deploying the DefaultWindows_Audit.xml policy on the system'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                Write-ColorfulText -Color Lavender -InputText 'The defaultWindows policy has been deployed in Audit mode. No reboot required.'

                Write-Verbose -Message 'Removing the generated .CIP files'
                Remove-Item -Path 'DefaultWindows_Audit.xml', "$PolicyID.cip" -Force
            }
            else {
                Write-ColorfulText -Color Lavender -InputText 'The defaultWindows policy has been created in Audit mode and is ready for deployment.'
            }
            Write-Progress -Id 8 -Activity 'Complete.' -Completed
        }

        Function Build-PolicyFromAuditLogs {
            <#
            .SYNOPSIS
                A helper function that creates 2 WDAC policies. A bas policy from one of the standard templates
                and a Supplemental policy based on the Code Integrity Operational audit logs
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.String
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 4
            [System.Int16]$CurrentStep = 0

            if ($MakePolicyFromAuditLogs -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            # Make sure there is no leftover files from previous operations of this same command
            Write-Verbose -Message 'Make sure there is no leftover files from previous operations of this same command'
            Remove-Item -Path "$Home\WDAC\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Create a working directory in user's folder
            Write-Verbose -Message 'Create a working directory in user folder'
            New-Item -Type Directory -Path "$Home\WDAC" -Force | Out-Null
            Set-Location "$Home\WDAC"

            #Region Base-Policy-Processing
            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Creating the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            switch ($BasePolicyType) {
                'Allow Microsoft Base' {
                    Write-Verbose -Message 'Creating Allow Microsoft Base policy'
                    Build-AllowMSFTWithBlockRules 6> $null
                    $Xml = [System.Xml.XmlDocument](Get-Content -Path .\AllowMicrosoftPlusBlockRules.xml)
                    $BasePolicyID = $Xml.SiPolicy.PolicyID
                    # define the location of the base policy
                    $BasePolicy = 'AllowMicrosoftPlusBlockRules.xml'
                }
                'Default Windows Base' {
                    Write-Verbose -Message 'Creating Default Windows Base policy'
                    Build-DefaultWindowsWithBlockRules 6> $null
                    $Xml = [System.Xml.XmlDocument](Get-Content -Path .\DefaultWindowsPlusBlockRules.xml)
                    $BasePolicyID = $Xml.SiPolicy.PolicyID
                    # define the location of the base policy
                    $BasePolicy = 'DefaultWindowsPlusBlockRules.xml'
                }
            }

            if ($TestMode -and $MakePolicyFromAuditLogs) {
                Write-Verbose -Message 'Setting "Boot Audit on Failure" and "Advanced Boot Options Menu" policy rule options because TestMode parameter was used'
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath $BasePolicy -Option $_ }
            }

            if ($RequireEVSigners -and $MakePolicyFromAuditLogs) {
                Write-Verbose -Message 'Setting "Required:EV Signers" policy rule option because RequireEVSigners parameter was used'
                Set-RuleOption -FilePath $BasePolicy -Option 8
            }
            #Endregion Base-Policy-Processing

            #Region Supplemental-Policy-Processing
            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Scanning the event logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                FilePath               = 'AuditLogsPolicy_NoDeletedFiles.xml'
                Audit                  = $true
                Level                  = $Level
                Fallback               = $Fallbacks
                MultiplePolicyFormat   = $true
                UserWriteablePaths     = $true
                WarningAction          = 'SilentlyContinue'
                AllowFileNameFallbacks = $true
            }
            # Assess user input parameters and add the required parameters to the hash table
            if ($SpecificFileNameLevel) { $PolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
            if ($NoScript) { $PolicyMakerHashTable['NoScript'] = $true }
            if (!$NoUserPEs) { $PolicyMakerHashTable['UserPEs'] = $true }

            Write-ColorfulText -Color HotPink -InputText 'Generating Supplemental policy with the following specifications:'
            $PolicyMakerHashTable
            Write-Host -Object ''

            # Create the supplemental policy via parameter splatting for files in event viewer that are currently on the disk
            New-CIPolicy @PolicyMakerHashTable

            if (!$NoDeletedFiles) {
                # Get Event viewer logs for code integrity - check the file path of all of the files in the log, resolve them using the command above - show files that are no longer available on the disk
                [System.Management.Automation.ScriptBlock]$AuditEventLogsDeletedFilesScriptBlock = {
                    foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 }) {
                        $Xml = [System.Xml.XmlDocument]$event.toxml()
                        $Xml.event.eventdata.data |
                        ForEach-Object -Begin { $Hash = @{} } -Process { $Hash[$_.name] = $_.'#text' } -End { [pscustomobject]$Hash } |
                        ForEach-Object -Process {
                            if ($_.'File Name' -match ($pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$')) {
                                $HardDiskVolumeNumber = $Matches[1]
                                $RemainingPath = $Matches[2]
                                $GetLetter = Get-GlobalRootDrives | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                                $UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                                $_.'File Name' = $_.'File Name' -replace $pattern, $UsablePath
                            }
                            if (-NOT (Test-Path -Path $_.'File Name')) {
                                $_ | Select-Object -Property FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                            }
                        }
                    }
                }
                # storing the output from the scriptblock above in a variable
                $DeletedFileHashesArray = Invoke-Command -ScriptBlock $AuditEventLogsDeletedFilesScriptBlock
            }
            # run the following only if there are any event logs for files no longer on the disk and if -NoDeletedFiles switch parameter wasn't used
            if ($DeletedFileHashesArray -and !$NoDeletedFiles) {

                # Save the the File Rules and File Rule Refs to the Out-File FileRulesAndFileRefs.txt in the current working directory
                    (Get-FileRules -HashesArray $DeletedFileHashesArray) + (Get-RuleRefs -HashesArray $DeletedFileHashesArray) | Out-File -FilePath FileRulesAndFileRefs.txt -Force

                # Put the Rules and RulesRefs in an empty policy file
                New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $DeletedFileHashesArray) -RuleRefsContent (Get-RuleRefs -HashesArray $DeletedFileHashesArray) | Out-File -FilePath .\DeletedFilesHashes.xml -Force

                # Merge the policy file we created at first using Event Viewer logs, with the policy file we created for Hash of the files no longer available on the disk
                Merge-CIPolicy -PolicyPaths 'AuditLogsPolicy_NoDeletedFiles.xml', .\DeletedFilesHashes.xml -OutputFilePath .\SupplementalPolicy.xml | Out-Null
            }
            # do this only if there are no event logs detected with files no longer on the disk, so we use the policy file created earlier using Audit even logs
            else {
                Rename-Item -Path 'AuditLogsPolicy_NoDeletedFiles.xml' -NewName 'SupplementalPolicy.xml' -Force
            }

            Write-Verbose -Message 'Setting the version for SupplementalPolicy.xml policy to 1.0.0.0'
            Set-CIPolicyVersion -FilePath 'SupplementalPolicy.xml' -Version '1.0.0.0'

            # Convert the SupplementalPolicy.xml policy file from base policy to supplemental policy of our base policy
            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Adjusting the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Convert the SupplementalPolicy.xml policy file from base policy to supplemental policy of our base policy'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath 'SupplementalPolicy.xml' -PolicyName "Supplemental Policy made from Audit Event Logs on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $BasePolicy
            [System.String]$PolicyID = $PolicyID.Substring(11)

            # Make sure policy rule options that don't belong to a Supplemental policy don't exist
            Write-Verbose -Message 'Setting the policy rule options for the Supplemental policy by making sure policy rule options that do not belong to a Supplemental policy do not exist'
            @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath 'SupplementalPolicy.xml' -Option $_ -Delete }

            # Set the hypervisor Code Integrity option for Supplemental policy to Strict
            Write-Verbose -Message 'Setting HVCI to strict for SupplementalPolicy.xml'
            Set-HVCIOptions -Strict -FilePath 'SupplementalPolicy.xml'

            # convert the Supplemental Policy file to .cip binary file
            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Generating the CIP files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Converting SupplementalPolicy.xml policy to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath 'SupplementalPolicy.xml' -BinaryFilePath "$PolicyID.cip" | Out-Null
            #Endregion Supplemental-Policy-Processing

            Write-ColorfulText -Color MintGreen -InputText "BasePolicyFile = $BasePolicy"
            Write-ColorfulText -Color MintGreen -InputText "BasePolicyGUID = $BasePolicyID"

            Write-ColorfulText -Color MintGreen -InputText 'SupplementalPolicyFile = SupplementalPolicy.xml'
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $PolicyID"

            if (-NOT $Debug) {
                Remove-Item -Path 'AuditLogsPolicy_NoDeletedFiles.xml', 'FileRulesAndFileRefs.txt', 'DeletedFilesHashes.xml' -Force -ErrorAction SilentlyContinue
            }

            if ($Deploy -and $MakePolicyFromAuditLogs) {
                Write-Verbose -Message 'Deploying the Base policy and Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$BasePolicyID.cip" -json | Out-Null
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null

                Write-ColorfulText -Color Pink -InputText 'Base policy and Supplemental Policies deployed and activated.'

                Write-Verbose -Message 'Getting the correct Prep mode Audit policy ID to remove from the system'
                switch ($BasePolicyType) {
                    'Allow Microsoft Base' {
                        Write-Verbose -Message 'Going to remove the AllowMicrosoft policy from the system because Allow Microsoft Base was used'
                        $IDToRemove = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.FriendlyName -eq 'PrepMSFTOnlyAudit' }).PolicyID
                    }
                    'Default Windows Base' {
                        Write-Verbose -Message 'Going to remove the DefaultWindows policy from the system because Default Windows Base was used'
                        $IDToRemove = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.FriendlyName -eq 'PrepDefaultWindows' }).PolicyID
                    }
                }

                &'C:\Windows\System32\CiTool.exe' --remove-policy "{$IDToRemove}" -json | Out-Null
                Write-ColorfulText -Color Lavender -InputText 'System restart required to finish removing the Audit mode Prep policy'
            }
            Write-Progress -Id 4 -Activity 'Complete.' -Completed
        }

        Function Build-LightPolicy {
            <#
            .SYNOPSIS
                A helper function that created SignedAndReputable WDAC policy
                which is based on AllowMicrosoft template policy.
                It includes Microsoft Recommended Block rules.
                It uses ISG to authorize files with good reputation.
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.String
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 5
            [System.Int16]$CurrentStep = 0

            # Delete any policy with the same name in the current working directory
            Remove-Item -Path 'SignedAndReputable.xml' -Force -ErrorAction SilentlyContinue

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Creating AllowMicrosoftPlusBlockRules policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Calling Build-AllowMSFTWithBlockRules function to create AllowMicrosoftPlusBlockRules.xml policy'
            # Redirecting the function's information Stream to $null because Write-Host
            # Used by Write-ColorfulText outputs to both information stream and host console
            Build-AllowMSFTWithBlockRules -NoCIP 6> $null

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Renaming AllowMicrosoftPlusBlockRules.xml to SignedAndReputable.xml'
            Rename-Item -Path 'AllowMicrosoftPlusBlockRules.xml' -NewName 'SignedAndReputable.xml' -Force

            Write-Verbose -Message 'Setting the policy rule options for the SignedAndReputable.xml policy'
            @(14, 15) | ForEach-Object -Process { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Configuring the policy rule options' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            if ($TestMode -and $MakeLightPolicy) {
                Write-Verbose -Message 'Setting "Boot Audit on Failure" and "Advanced Boot Options Menu" policy rule options because TestMode parameter was used'
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }
            }
            if ($RequireEVSigners -and $MakeLightPolicy) {
                Write-Verbose -Message 'Setting "Required:EV Signers" policy rule option because RequireEVSigners parameter was used'
                Set-RuleOption -FilePath .\SignedAndReputable.xml -Option 8
            }

            Write-Verbose -Message 'Resetting the policy ID and setting a name for SignedAndReputable.xml'
            $BasePolicyID = Set-CIPolicyIdInfo -FilePath .\SignedAndReputable.xml -ResetPolicyID -PolicyName "Signed And Reputable policy - $(Get-Date -Format 'MM-dd-yyyy')"
            $BasePolicyID = $BasePolicyID.Substring(11)

            Write-Verbose -Message 'Setting the version of SignedAndReputable.xml policy to 1.0.0.0'
            Set-CIPolicyVersion -FilePath .\SignedAndReputable.xml -Version '1.0.0.0'

            Write-Verbose -Message 'Setting HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath .\SignedAndReputable.xml

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Converting SignedAndReputable.xml policy to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath .\SignedAndReputable.xml -BinaryFilePath "$BasePolicyID.cip" | Out-Null

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Configuring Windows Services' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Configuring required services for ISG authorization'
            Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -NoNewWindow
            Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -NoNewWindow

            if ($Deploy -and $MakeLightPolicy) {
                Write-Verbose -Message 'Deploying the SignedAndReputable.xml policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$BasePolicyID.cip" -json | Out-Null
            }

            Write-Verbose -Message 'Displaying the output'
            Write-ColorfulText -Color MintGreen -InputText 'BasePolicyFile = SignedAndReputable.xml'
            Write-ColorfulText -Color MintGreen -InputText "BasePolicyGUID = $BasePolicyID"

            Write-Progress -Id 6 -Activity 'Complete.' -Completed
        }

        # Script block that is used to supply extra information regarding Microsoft recommended driver block rules in commands that use them
        [System.Management.Automation.ScriptBlock]$DriversBlockListInfoGatheringSCRIPTBLOCK = {
            [System.String]$owner = 'MicrosoftDocs'
            [System.String]$repo = 'windows-itpro-docs'
            [System.String]$path = 'windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md'

            [System.String]$ApiUrl = "https://api.github.com/repos/$owner/$repo/commits?path=$path"
            [System.Object[]]$Response = Invoke-RestMethod -Uri $ApiUrl -ProgressAction SilentlyContinue
            [System.DateTime]$Date = $Response[0].commit.author.date

            Write-ColorfulText -Color Lavender -InputText "The document containing the drivers block list on GitHub was last updated on $Date"
            [System.String]$MicrosoftRecommendedDriverBlockRules = (Invoke-WebRequest -Uri $MSFTRecommendedDriverBlockRulesURL -ProgressAction SilentlyContinue).Content
            $MicrosoftRecommendedDriverBlockRules -match '<VersionEx>(.*)</VersionEx>' | Out-Null
            Write-ColorfulText -Color Pink -InputText "The current version of Microsoft recommended drivers block list is $($Matches[1])"
        }

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }
    }

    process {

        switch ($true) {
            # Deploy the latest block rules
            { $GetBlockRules -and $Deploy } { Deploy-LatestBlockRules ; break }
            # Get the latest block rules
            $GetBlockRules { Get-BlockRulesMeta ; break }
            # Get the latest driver block rules and Deploy them if New-WDACConfig -GetDriverBlockRules was called with -Deploy parameter
            { $GetDriverBlockRules } { Get-DriverBlockRules -Deploy:$Deploy ; break }
            $SetAutoUpdateDriverBlockRules { Set-AutoUpdateDriverBlockRules ; break }
            $MakeAllowMSFTWithBlockRules { Build-AllowMSFTWithBlockRules ; break }
            $MakePolicyFromAuditLogs { Build-PolicyFromAuditLogs ; break }
            $PrepMSFTOnlyAudit { Build-MSFTOnlyAudit ; break }
            $MakeLightPolicy { Build-LightPolicy ; break }
            $MakeDefaultWindowsWithBlockRules { Build-DefaultWindowsWithBlockRules ; break }
            $PrepDefaultWindowsAudit { Build-DefaultWindowsAudit ; break }
            default { Write-Warning -Message 'None of the main parameters were selected.'; break }
        }
    }

    <#
.SYNOPSIS
    Automate a lot of tasks related to WDAC (Windows Defender Application Control)
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig
.DESCRIPTION
    Using official Microsoft methods, configure and use Windows Defender Application Control
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Automate various tasks related to Windows Defender Application Control (WDAC)
.PARAMETER GetBlockRules
    Create Microsoft recommended block rules xml policy and remove the allow rules
.PARAMETER GetDriverBlockRules
    Create Microsoft recommended driver block rules xml policy and remove the allow rules
.PARAMETER MakeAllowMSFTWithBlockRules
    Make WDAC policy by merging AllowMicrosoft policy with the recommended block rules
.PARAMETER SetAutoUpdateDriverBlockRules
    Make a Scheduled Task that automatically runs every 7 days to download the newest Microsoft Recommended driver block rules
.PARAMETER PrepMSFTOnlyAudit
    Prepare the system for Audit mode using AllowMicrosoft default policy
.PARAMETER PrepDefaultWindowsAudit
    Prepare the system for Audit mode using DefaultWindows policy
.PARAMETER MakePolicyFromAuditLogs
    Make a WDAC Policy from Audit event logs that also covers files no longer on disk
.PARAMETER MakeLightPolicy
    Make a WDAC Policy with ISG for Lightly Managed system
.PARAMETER MakeDefaultWindowsWithBlockRules
    Make a WDAC policy by merging DefaultWindows policy with the recommended block rules
.PARAMETER BasePolicyType
    Select the Base Policy Type
.PARAMETER Deploy
    Deploys the policy that is being created
.PARAMETER IncludeSignTool
    Indicates that the Default Windows policy that is being created must include Allow rules for SignTool.exe - This parameter must be used when you intend to Sign and Deploy the Default Windows policy.
.PARAMETER SignToolPath
    Path to the SignTool.exe file - Optional
.PARAMETER TestMode
    Indicates that the created/deployed policy will have Enabled:Boot Audit on Failure and Enabled:Advanced Boot Options Menu policy rule options
.PARAMETER RequireEVSigners
    Indicates that the created/deployed policy will have Require EV Signers policy rule option.
.PARAMETER NoDeletedFiles
    Indicates that files that were run during program installations but then were deleted and are no longer on the disk, won't be added to the supplemental policy. This can mean the programs you installed will be allowed to run but installation/reinstallation might not be allowed once the policies are deployed.
.PARAMETER SpecificFileNameLevel
    You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath". More info available on Microsoft Learn
.PARAMETER NoUserPEs
    By default, the module includes user PEs in the scan. When you use this switch parameter, they won't be included.
.PARAMETER NoScript
    Won't scan script files
.PARAMETER Level
    Offers the same official Levels for scanning of event logs. If no level is specified the default, which is set to FilePublisher in this module, will be used.
.PARAMETER Fallbacks
    Offers the same official Fallbacks for scanning of event logs. If no fallbacks are specified the default, which is set to Hash in this module, will be used.
.PARAMETER LogSize
    Specifies the log size for Microsoft-Windows-CodeIntegrity/Operational events. The values must be in the form of <Digit + Data measurement unit>. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.
    The maximum range is the maximum allowed log size by Windows Event viewer
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.PARAMETER Verbose
    Displays detailed information about the operation performed by the command
.INPUTS
    System.Int64
    System.String[]
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    New-WDACConfig -GetBlockRules -Deploy
    This example will create a WDAC policy with Microsoft recommended block rules and deploys it on the system
.EXAMPLE
    New-WDACConfig -GetDriverBlockRules -Deploy
    This example will create a WDAC policy with Microsoft recommended driver block rules and deploys it on the system
.EXAMPLE
    New-WDACConfig -MakeAllowMSFTWithBlockRules -Deploy
    This example will create a WDAC policy by merging AllowMicrosoft policy with the recommended block rules and deploys it on the system
.EXAMPLE
    New-WDACConfig -SetAutoUpdateDriverBlockRules
    This example will create a Scheduled Task that automatically runs every 7 days to download the newest Microsoft Recommended driver block rules
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'New-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAfrDb69NwFix6M
# PswLnpYW+kqgyt0divbGUXmo+hk9xqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
# LDQz/68TAAAAAAAEMA0GCSqGSIb3DQEBDQUAME8xEzARBgoJkiaJk/IsZAEZFgNj
# b20xIjAgBgoJkiaJk/IsZAEZFhJIT1RDQUtFWC1DQS1Eb21haW4xFDASBgNVBAMT
# C0hPVENBS0VYLUNBMCAXDTIzMTIyNzExMjkyOVoYDzIyMDgxMTEyMTEyOTI5WjB5
# MQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVSG90Q2FrZVggQ29kZSBTaWduaW5nMSMw
# IQYJKoZIhvcNAQkBFhRob3RjYWtleEBvdXRsb29rLmNvbTElMCMGCSqGSIb3DQEJ
# ARYWU3B5bmV0Z2lybEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAKb1BJzTrpu1ERiwr7ivp0UuJ1GmNmmZ65eckLpGSF+2r22+7Tgm
# pEifj9NhPw0X60F9HhdSM+2XeuikmaNMvq8XRDUFoenv9P1ZU1wli5WTKHJ5ayDW
# k2NP22G9IPRnIpizkHkQnCwctx0AFJx1qvvd+EFlG6ihM0fKGG+DwMaFqsKCGh+M
# rb1bKKtY7UEnEVAsVi7KYGkkH+ukhyFUAdUbh/3ZjO0xWPYpkf/1ldvGes6pjK6P
# US2PHbe6ukiupqYYG3I5Ad0e20uQfZbz9vMSTiwslLhmsST0XAesEvi+SJYz2xAQ
# x2O4n/PxMRxZ3m5Q0WQxLTGFGjB2Bl+B+QPBzbpwb9JC77zgA8J2ncP2biEguSRJ
# e56Ezx6YpSoRv4d1jS3tpRL+ZFm8yv6We+hodE++0tLsfpUq42Guy3MrGQ2kTIRo
# 7TGLOLpayR8tYmnF0XEHaBiVl7u/Szr7kmOe/CfRG8IZl6UX+/66OqZeyJ12Q3m2
# fe7ZWnpWT5sVp2sJmiuGb3atFXBWKcwNumNuy4JecjQE+7NF8rfIv94NxbBV/WSM
# pKf6Yv9OgzkjY1nRdIS1FBHa88RR55+7Ikh4FIGPBTAibiCEJMc79+b8cdsQGOo4
# ymgbKjGeoRNjtegZ7XE/3TUywBBFMf8NfcjF8REs/HIl7u2RHwRaUTJdAgMBAAGj
# ggJzMIICbzA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiG7sUghM++I4HxhQSF
# hqV1htyhDXuG5sF2wOlDAgFkAgEIMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1Ud
# DwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYB
# BQUHAwMwHQYDVR0OBBYEFOlnnQDHNUpYoPqECFP6JAqGDFM6MB8GA1UdIwQYMBaA
# FICT0Mhz5MfqMIi7Xax90DRKYJLSMIHUBgNVHR8EgcwwgckwgcaggcOggcCGgb1s
# ZGFwOi8vL0NOPUhPVENBS0VYLUNBLENOPUhvdENha2VYLENOPUNEUCxDTj1QdWJs
# aWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1cmF0aW9u
# LERDPU5vbkV4aXN0ZW50RG9tYWluLERDPWNvbT9jZXJ0aWZpY2F0ZVJldm9jYXRp
# b25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9uUG9pbnQwgccG
# CCsGAQUFBwEBBIG6MIG3MIG0BggrBgEFBQcwAoaBp2xkYXA6Ly8vQ049SE9UQ0FL
# RVgtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
# Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9Tm9uRXhpc3RlbnREb21haW4sREM9Y29t
# P2NBQ2VydGlmaWNhdGU/YmFzZT9vYmplY3RDbGFzcz1jZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5MA0GCSqGSIb3DQEBDQUAA4ICAQA7JI76Ixy113wNjiJmJmPKfnn7brVI
# IyA3ZudXCheqWTYPyYnwzhCSzKJLejGNAsMlXwoYgXQBBmMiSI4Zv4UhTNc4Umqx
# pZSpqV+3FRFQHOG/X6NMHuFa2z7T2pdj+QJuH5TgPayKAJc+Kbg4C7edL6YoePRu
# HoEhoRffiabEP/yDtZWMa6WFqBsfgiLMlo7DfuhRJ0eRqvJ6+czOVU2bxvESMQVo
# bvFTNDlEcUzBM7QxbnsDyGpoJZTx6M3cUkEazuliPAw3IW1vJn8SR1jFBukKcjWn
# aau+/BE9w77GFz1RbIfH3hJ/CUA0wCavxWcbAHz1YoPTAz6EKjIc5PcHpDO+n8Fh
# t3ULwVjWPMoZzU589IXi+2Ol0IUWAdoQJr/Llhub3SNKZ3LlMUPNt+tXAs/vcUl0
# 7+Dp5FpUARE2gMYA/XxfU9T6Q3pX3/NRP/ojO9m0JrKv/KMc9sCGmV9sDygCOosU
# 5yGS4Ze/DJw6QR7xT9lMiWsfgL96Qcw4lfu1+5iLr0dnDFsGowGTKPGI0EvzK7H+
# DuFRg+Fyhn40dOUl8fVDqYHuZJRoWJxCsyobVkrX4rA6xUTswl7xYPYWz88WZDoY
# gI8AwuRkzJyUEA07IYtsbFCYrcUzIHME4uf8jsJhCmb0va1G2WrWuyasv3K/G8Nn
# f60MsDbDH1mLtzGCAxgwggMUAgEBMGYwTzETMBEGCgmSJomT8ixkARkWA2NvbTEi
# MCAGCgmSJomT8ixkARkWEkhPVENBS0VYLUNBLURvbWFpbjEUMBIGA1UEAxMLSE9U
# Q0FLRVgtQ0ECEx4AAAAEjzQsNDP/rxMAAAAAAAQwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQg14hf2M6F3YKfWHTxS9cZtCQlYAMlxYCw6pIEjXWMeRMwDQYJKoZIhvcNAQEB
# BQAEggIAUmu4Ste9ajEpKCdiTAaDt1llyJJ0kAtR9nsj1z45Qmxt9z1gb6l2tIZ2
# Dn5zedSmLVY99cL4D3682cvGWz++4SPDRzzdSZ4HU64CyYr7BVQSmhz2LajKv9ev
# bKOOaLEHO/nVl/iH1Oa+zXW4WmbfLUr8EW7QBKgxNMRm+3IViw0BvQAcTe8r9OHA
# 8wOXDL3B/zptm0+xyJg9xOuldLK0Xl261G53zMRytYynEi+YpzBAsY1K0wd6CbR+
# C/5RfIwdh8OLe33vHgEK60VIL/Y5RfYGDRy5FJbaw62OQ1+BEwFdvdzlbUR/Fytk
# rWQvELyAz6eveV3iq/iRjzEgGl+yJqM6uz8AYyJgGyBT4FrCUiMZZrokiCuR74Zb
# ADQKG8hzRshGENCYdCXt1074N/5E0UhxgRcatf5uEFcXaxpDSRiY7V2cv4EI3scd
# ipHt2Uvl50bPLEoykWP0xRQU9d3WktkX6/4vA73LO3l2edsYsWtUtaek1giJqY+4
# R/TMeHlRD56PY/ObkKL/xpssSO1reIF+NR80HdCh+CkPZJ3OF6utchZt7dFFgkBV
# WQid6pST1aObgMD3B4+ZtaAORlFy1TekNeDKyusj2fRUYPeQJ2kozjjP+7XponBQ
# MUq7XO8lz/Wq16usJ3mFzDV+ebIbkQDobAZN5evRVGFFD65Q0eo=
# SIG # End signature block
