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
        # If User is creating Default Windows policy and including SignTool path
        if ($IncludeSignTool -and $MakeDefaultWindowsWithBlockRules) {
            # Read User configuration file if it exists
            $UserConfig = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue
            if ($UserConfig) {
                # Validate the Json file and read its content to make sure it's not corrupted
                try { $UserConfig = $UserConfig | ConvertFrom-Json }
                catch {
                    Write-Error -Message 'User Configurations Json file is corrupted, deleting it...' -ErrorAction Continue
                    Remove-CommonWDACConfig
                }
            }
        }

        # Get SignToolPath from user parameter or user config file or auto-detect it
        if ($SignToolPath) {
            $SignToolPathFinal = Get-SignTool -SignToolExePath $SignToolPath
        } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
        elseif ($IncludeSignTool -and $MakeDefaultWindowsWithBlockRules) {
            $SignToolPathFinal = Get-SignTool -SignToolExePath ($UserConfig.SignToolCustomPath ?? $null)
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

            if ($Deploy) {
                Write-Verbose -Message 'Downloading the Microsoft Recommended Driver Block List archive'
                Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile VulnerableDriverBlockList.zip -ProgressAction SilentlyContinue

                Write-Verbose -Message 'Expanding the Block list archive'
                Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath 'VulnerableDriverBlockList' -Force

                Write-Verbose -Message 'Renaming the block list file to SiPolicy.p7b'
                Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName 'SiPolicy.p7b' -Force

                Write-Verbose -Message 'Copying the new block list to the CodeIntegrity folder, replacing any old ones'
                Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination 'C:\Windows\System32\CodeIntegrity' -Force

                Write-Verbose -Message 'Refreshing the system WDAC policies using CiTool.exe'
                &'C:\Windows\System32\CiTool.exe' --refresh -json | Out-Null

                Write-ColorfulText -Color Pink -InputText 'SiPolicy.p7b has been deployed and policies refreshed.'

                Write-Verbose -Message 'Cleaning up'
                Remove-Item -Path .\VulnerableDriverBlockList* -Recurse -Force

                Write-Verbose -Message 'Displaying extra info about the Microsoft recommended Drivers block list'
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
            }
            else {
                # Downloading the latest Microsoft Recommended Driver Block Rules from the official source
                Write-Verbose -Message 'Downloading the latest Microsoft Recommended Driver Block Rules from the official source'
                [System.String]$DriverRules = (Invoke-WebRequest -Uri $MSFTRecommendedDriverBlockRulesURL -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1'

                # Remove the unnecessary rules and elements - not using this one because then during the merge there will be error - The reason is that "<FileRuleRef RuleID="ID_ALLOW_ALL_2" />" is the only FileruleRef in the xml and after removing it, the <SigningScenario> element will be empty
                Write-Verbose -Message 'Removing the allow all rules and rule refs from the policy'
                $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_[12]"\sFriendlyName=""\sFileName="\*".*/>', ''
                $DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_1".*/>', ''
                $DriverRules = $DriverRules -replace '<SigningScenario\sValue="12"\sID="ID_SIGNINGSCENARIO_WINDOWS"\sFriendlyName="Auto\sgenerated\spolicy[\S\s]*<\/SigningScenario>', ''

                # Output the XML content to a file
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
            # Get the latest Microsoft recommended block rules
            Write-Verbose -Message 'Getting the latest Microsoft recommended block rules'
            Get-BlockRulesMeta 6> $null

            Write-Verbose -Message 'Copying the AllowMicrosoft.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination 'AllowMicrosoft.xml' -Force

            Write-Verbose -Message 'Merging the AllowMicrosoft.xml with Microsoft Recommended Block rules.xml'
            Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\AllowMicrosoftPlusBlockRules.xml | Out-Null

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

            Write-Verbose -Message 'Getting the latest Microsoft recommended block rules'
            Get-BlockRulesMeta 6> $null

            Write-Verbose -Message 'Copying the DefaultWindows_Enforced.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination 'DefaultWindows_Enforced.xml' -Force

            # Setting a flag for Scanning the SignTool.exe and merging it with the final base policy
            [System.Boolean]$MergeSignToolPolicy = $false

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

            # Scan PowerShell core directory and allow its files in the Default Windows base policy so that module can still be used once it's been deployed
            if (Test-Path -Path 'C:\Program Files\PowerShell') {

                Write-ColorfulText -Color Lavender -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                New-CIPolicy -ScanPath 'C:\Program Files\PowerShell' -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml

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

            Write-Verbose -Message 'Converting the DefaultWindowsPlusBlockRules.xml policy file to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath .\DefaultWindowsPlusBlockRules.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

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

            Write-Verbose -Message 'Downloading the latest Microsoft recommended block rules and creating Microsoft recommended block rules TEMP.xml'
            (Invoke-WebRequest -Uri $MSFTRecommendedBlockRulesURL -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1' | Out-File -FilePath '.\Microsoft recommended block rules TEMP.xml' -Force

            # Remove empty lines from the policy file
            Write-Verbose -Message 'Removing any empty lines from the Temp policy file and generating the Microsoft recommended block rules.xml'
            Get-Content -Path '.\Microsoft recommended block rules TEMP.xml' | Where-Object -FilterScript { $_.trim() -ne '' } | Out-File -FilePath '.\Microsoft recommended block rules.xml' -Force

            Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option 3 -Delete
            @(0, 2, 6, 11, 12, 16, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option $_ }
            Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.xml'
            Remove-Item -Path '.\Microsoft recommended block rules TEMP.xml' -Force
            [System.String]$PolicyID = (Set-CIPolicyIdInfo -FilePath '.\Microsoft recommended block rules.xml' -ResetPolicyID).Substring(11)
            Set-CIPolicyIdInfo -PolicyName "Microsoft Windows User Mode Policy - Enforced - $(Get-Date -Format 'MM-dd-yyyy')" -FilePath '.\Microsoft recommended block rules.xml'
            ConvertFrom-CIPolicy -XmlFilePath '.\Microsoft recommended block rules.xml' -BinaryFilePath "$PolicyID.cip" | Out-Null
            &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
            Write-ColorfulText -Color Lavender -InputText 'The Microsoft recommended block rules policy has been deployed in enforced mode.'
            Remove-Item -Path "$PolicyID.cip" -Force
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
                    -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit 1};Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "$env:SystemDrive\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item -Path .\VulnerableDriverBlockList -Recurse -Force;Remove-Item -Path .\VulnerableDriverBlockList.zip -Force; exit 0;}"'

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

            if ($PrepMSFTOnlyAudit -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            Write-Verbose -Message 'Copying AllowMicrosoft.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination .\AllowMicrosoft.xml -Force

            Write-Verbose -Message 'Enabling Audit mode'
            Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option 3

            Write-Verbose -Message 'Resetting the Policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Assigning "PrepMSFTOnlyAudit" as the policy name'
            Set-CIPolicyIdInfo -PolicyName 'PrepMSFTOnlyAudit' -FilePath .\AllowMicrosoft.xml

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

            if ($PrepDefaultWindowsAudit -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            Write-Verbose -Message 'Copying DefaultWindows_Audit.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml' -Destination .\DefaultWindows_Audit.xml -Force

            # Making Sure neither PowerShell core nor WDACConfig module files are added to the Supplemental policy created by -MakePolicyFromAuditLogs parameter
            # by adding them first to the deployed Default Windows policy in Audit mode. Because WDACConfig module files don't need to be allowed to run since they are *.ps1 and .*psm1 files
            # And PowerShell core files will be added to the DefaultWindows Base policy anyway
            if (Test-Path -Path 'C:\Program Files\PowerShell') {
                Write-Verbose -Message 'Scanning PowerShell core directory and creating a policy file'
                New-CIPolicy -ScanPath 'C:\Program Files\PowerShell' -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml

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

            Write-Verbose -Message 'Enabling Audit mode'
            Set-RuleOption -FilePath .\DefaultWindows_Audit.xml -Option 3

            Write-Verbose -Message 'Resetting the Policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\DefaultWindows_Audit.xml -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Assigning "PrepDefaultWindowsAudit" as the policy name'
            Set-CIPolicyIdInfo -PolicyName 'PrepDefaultWindows' -FilePath .\DefaultWindows_Audit.xml

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

            if ($MakePolicyFromAuditLogs -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            # Make sure there is no leftover files from previous operations of this same command
            Write-Verbose -Message 'Make sure there is no leftover files from previous operations of this same command'
            Remove-Item -Path "$home\WDAC\*" -Recurse -Force -ErrorAction SilentlyContinue

            # Create a working directory in user's folder
            Write-Verbose -Message 'Create a working directory in user folder'
            New-Item -Type Directory -Path "$home\WDAC" -Force | Out-Null
            Set-Location "$home\WDAC"

            #Region Base-Policy-Processing
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
            # Produce a policy xml file from event viewer logs
            Write-ColorfulText -Color Lavender -InputText 'Scanning Windows Event logs and creating a policy file, please wait...'

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
                        ForEach-Object -Begin { $Hash = @{} } -Process { $hash[$_.name] = $_.'#text' } -End { [pscustomobject]$hash } |
                        ForEach-Object -Process {
                            if ($_.'File Name' -match ($pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$')) {
                                $hardDiskVolumeNumber = $Matches[1]
                                $remainingPath = $Matches[2]
                                $getletter = Get-GlobalRootDrives | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$hardDiskVolumeNumber" }
                                $usablePath = "$($getletter.DriveLetter)$remainingPath"
                                $_.'File Name' = $_.'File Name' -replace $pattern, $usablePath
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

                Write-ColorfulText -Color Pink -InputText "`nBase policy and Supplemental Policies deployed and activated.`n"

                # Get the correct Prep mode Audit policy ID to remove from the system
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
                Write-ColorfulText -Color Lavender -InputText "`nSystem restart required to finish removing the Audit mode Prep policy"
            }
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

            # Delete any policy with the same name in the current working directory
            Remove-Item -Path 'SignedAndReputable.xml' -Force -ErrorAction SilentlyContinue

            Write-Verbose -Message 'Calling Build-AllowMSFTWithBlockRules function to create AllowMicrosoftPlusBlockRules.xml policy'
            # Redirecting the function's information Stream to $null because Write-Host
            # Used by Write-ColorfulText outputs to both information stream and host console
            Build-AllowMSFTWithBlockRules -NoCIP 6> $null

            Write-Verbose -Message 'Renaming AllowMicrosoftPlusBlockRules.xml to SignedAndReputable.xml'
            Rename-Item -Path 'AllowMicrosoftPlusBlockRules.xml' -NewName 'SignedAndReputable.xml' -Force

            Write-Verbose -Message 'Setting the policy rule options for the SignedAndReputable.xml policy'
            @(14, 15) | ForEach-Object -Process { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }

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

            Write-Verbose -Message 'Converting SignedAndReputable.xml policy to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath .\SignedAndReputable.xml -BinaryFilePath "$BasePolicyID.cip" | Out-Null

            # Configure required services for ISG authorization
            Write-Verbose -Message 'Configuring required services for ISG authorization'
            Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -Wait -NoNewWindow
            Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -Wait -NoNewWindow

            if ($Deploy -and $MakeLightPolicy) {
                Write-Verbose -Message 'Deploying the SignedAndReputable.xml policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$BasePolicyID.cip" -json | Out-Null
            }

            Write-Verbose -Message 'Displaying the output'
            Write-ColorfulText -Color MintGreen -InputText 'BasePolicyFile = SignedAndReputable.xml'
            Write-ColorfulText -Color MintGreen -InputText "BasePolicyGUID = $BasePolicyID"
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
.INPUTS
    System.Int64
    System.String[]
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'New-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
