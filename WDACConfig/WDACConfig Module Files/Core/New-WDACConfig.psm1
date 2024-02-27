Function New-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Get Block Rules',
        PositionalBinding = $false
    )]
    [OutputType([System.String])]
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

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [ValidateRange(1024KB, 18014398509481983KB)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep MSFT Only Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep Default Windows Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.UInt64]$LogSize,

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
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Set-LogSize.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-EmptyPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-RuleRefs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-FileRules.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-BlockRulesMeta.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Edit-CiPolicyRuleOptions.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-StagingArea.psm1" -Force

        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'New-WDACConfig'

        Function Get-DriverBlockRules {
            <#
            .SYNOPSIS
                Gets the latest Microsoft Recommended Driver Block rules and processes them
                Can optionally deploy them.
                If the -Deploy switch is used, the drivers block list will contain the 2 allow all rules,
                otherwise, the allow all rules will be removed from the policy
            .INPUTS
                System.Management.Automation.SwitchParameter
            .OUTPUTS
                System.String
            .PARAMETER Deploy
                Indicates that the function will deploy the latest Microsoft recommended drivers block list
            #>
            [CmdletBinding()]
            [OutputType([System.String])]
            param (
                [System.Management.Automation.SwitchParameter]$Deploy
            )

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = 3
            [System.UInt16]$CurrentStep = 0

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Downloading the driver block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Downloading the Microsoft Recommended Driver Block List archive'
                Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile (Join-Path -Path $StagingArea -ChildPath 'VulnerableDriverBlockList.zip') -ProgressAction SilentlyContinue

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Expanding the archive' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Expanding the Block list archive'
                Expand-Archive -Path (Join-Path -Path $StagingArea -ChildPath 'VulnerableDriverBlockList.zip') -DestinationPath (Join-Path -Path $StagingArea -ChildPath 'VulnerableDriverBlockList') -Force

                Write-Verbose -Message 'Renaming and copying the new block list to the CodeIntegrity folder, replacing any old ones'
                Move-Item -Path (Join-Path -Path $StagingArea -ChildPath 'VulnerableDriverBlockList' -AdditionalChildPath 'SiPolicy_Enforced.p7b') -Destination 'C:\Windows\System32\CodeIntegrity\SiPolicy.p7b' -Force

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Refreshing the system policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Refreshing the system WDAC policies using CiTool.exe'
                &'C:\Windows\System32\CiTool.exe' --refresh -json | Out-Null

                Write-ColorfulText -Color Pink -InputText 'SiPolicy.p7b has been deployed and policies refreshed.'

                Write-Verbose -Message 'Displaying extra info about the Microsoft recommended Drivers block list'
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
            }
            else {
                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Downloading the driver block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Download the markdown page from GitHub containing the latest Microsoft recommended driver block rules
                [System.String]$MSFTDriverBlockRulesAsString = (Invoke-WebRequest -Uri $MSFTRecommendedDriverBlockRulesURL -ProgressAction SilentlyContinue).Content

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Removing the `Allow all rules` from the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Load the Driver Block Rules as XML into a variable after extracting them from the markdown string
                [System.Xml.XmlDocument]$DriverBlockRulesXML = ($MSFTDriverBlockRulesAsString -replace "(?s).*``````xml(.*)``````.*", '$1').Trim()

                # Get the SiPolicy node
                [System.Xml.XmlElement]$SiPolicyNode = $DriverBlockRulesXML.SiPolicy

                # Declare the namespace manager and add the default namespace with a prefix
                [System.Xml.XmlNamespaceManager]$NameSpace = New-Object -TypeName System.Xml.XmlNamespaceManager -ArgumentList $DriverBlockRulesXML.NameTable
                $NameSpace.AddNamespace('ns', 'urn:schemas-microsoft-com:sipolicy')

                # Select the FileRuleRef nodes that have a RuleID attribute that starts with ID_ALLOW_
                [System.Object[]]$NodesToRemove = $SiPolicyNode.FileRules.SelectNodes("//ns:FileRuleRef[starts-with(@RuleID, 'ID_ALLOW_')]", $NameSpace)

                # Append the Allow nodes that have an ID attribute that starts with ID_ALLOW_ to the array
                $NodesToRemove += $SiPolicyNode.FileRules.SelectNodes("//ns:Allow[starts-with(@ID, 'ID_ALLOW_')]", $NameSpace)

                # Loop through the nodes to remove
                foreach ($Node in $NodesToRemove) {
                    # Get the parent node of the node to remove
                    [System.Xml.XmlElement]$ParentNode = $Node.ParentNode

                    # Check if the parent node has more than one child node, if it does then only remove the child node
                    if ($ParentNode.ChildNodes.Count -gt 1) {
                        # Remove the node from the parent node
                        $ParentNode.RemoveChild($Node) | Out-Null
                    }

                    # If the parent node only has one child node then replace the parent node with an empty node
                    else {
                        # Create a new node with the same name and namespace as the parent node
                        [System.Xml.XmlElement]$NewNode = $DriverBlockRulesXML.CreateElement($ParentNode.Name, $ParentNode.NamespaceURI)
                        # Replace the parent node with the new node
                        $ParentNode.ParentNode.ReplaceChild($NewNode, $ParentNode) | Out-Null

                        # Check if the new node has any sibling nodes, if not then replace its parent node with an empty node
                        # We do this because the built-in PowerShell cmdlets would throw errors if empty <FileRulesRef /> exists inside <ProductSigners> node
                        if ($null -eq $NewNode.PreviousSibling -and $null -eq $NewNode.NextSibling) {

                            # Get the grandparent node of the new node
                            [System.Xml.XmlElement]$GrandParentNode = $NewNode.ParentNode

                            # Create a new node with the same name and namespace as the grandparent node
                            [System.Xml.XmlElement]$NewGrandNode = $DriverBlockRulesXML.CreateElement($GrandParentNode.Name, $GrandParentNode.NamespaceURI)

                            # Replace the grandparent node with the new node
                            $GrandParentNode.ParentNode.ReplaceChild($NewGrandNode, $GrandParentNode) | Out-Null
                        }
                    }
                }

                [System.IO.FileInfo]$XMLPath = Join-Path -Path $StagingArea -ChildPath 'Microsoft recommended driver block rules.xml'

                # Save the modified XML content to a file
                $DriverBlockRulesXML.Save($XMLPath)

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Removing the Audit mode policy rule option'
                Set-RuleOption -FilePath $XMLPath -Option 3 -Delete

                Write-Verbose -Message 'Setting the HVCI option to strict'
                Set-HVCIOptions -Strict -FilePath $XMLPath

                Write-Verbose -Message 'Displaying extra info about the Microsoft recommended Drivers block list'
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK

                # Copy the result to the User Config directory at the end
                Copy-Item -Path $XMLPath -Destination $UserConfigDir -Force

                Write-ColorfulText -Color MintGreen -InputText "PolicyFile = $($XMLPath.Name)"
            }
            Write-Progress -Id 1 -Activity 'Complete.' -Completed
        }

        Function Build-AllowMSFTWithBlockRules {
            <#
            .SYNOPSIS
                A helper function that downloads the latest Microsoft recommended block rules
                and merges them with the Allow Microsoft template policy.
                It can also deploy the policy on the system.
            .INPUTS
                System.Management.Automation.SwitchParameter
            .OUTPUTS
                System.String
            .PARAMETER Deploy
                Indicates that the function will deploy the AllowMicrosoftPlusBlockRules policy
            #>
            [CmdletBinding()]
            param (
                [System.Management.Automation.SwitchParameter]$Deploy
            )

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 4 : 3
            [System.UInt16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Getting the recommended block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Getting the latest Microsoft recommended block rules'
            Push-Location -Path $StagingArea
            Get-BlockRulesMeta 6> $null
            Pop-Location

            Write-Verbose -Message 'Copying the AllowMicrosoft.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination (Join-Path -Path $StagingArea -ChildPath 'AllowMicrosoft.xml') -Force

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Merging the block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath 'AllowMicrosoftPlusBlockRules.xml'

            Write-Verbose -Message 'Merging the AllowMicrosoft.xml with Microsoft Recommended Block rules.xml'
            Merge-CIPolicy -PolicyPaths (Join-Path -Path $StagingArea -ChildPath 'AllowMicrosoft.xml'), (Join-Path -Path $StagingArea -ChildPath 'Microsoft recommended block rules.xml') -OutputFilePath $FinalPolicyPath | Out-Null

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and setting a name for AllowMicrosoftPlusBlockRules.xml'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -PolicyName "Allow Microsoft Plus Block Rules - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting AllowMicrosoftPlusBlockRules.xml policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalPolicyPath -Version '1.0.0.0'

            Edit-CiPolicyRuleOptions -Action Base -XMLFile $FinalPolicyPath

            if ($TestMode -and $MakeAllowMSFTWithBlockRules) {
                Write-Verbose -Message 'Setting "Boot Audit on Failure" and "Advanced Boot Options Menu" policy rule options for the AllowMicrosoftPlusBlockRules.xml policy because TestMode parameter was used'
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath $FinalPolicyPath -Option $_ }
            }
            if ($RequireEVSigners -and $MakeAllowMSFTWithBlockRules) {
                Write-Verbose -Message 'Setting "Required:EV Signers" policy rule option for the AllowMicrosoftPlusBlockRules.xml policy because RequireEVSigners parameter was used'
                Set-RuleOption -FilePath $FinalPolicyPath -Option 8
            }

            if ($Deploy -and $MakeAllowMSFTWithBlockRules) {
                $CurrentStep++
                Write-Progress -Id 3 -Activity 'Creating CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the AllowMicrosoftPlusBlockRules.xml policy file to .CIP binary'
                ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath "$PolicyID.cip" | Out-Null

                Write-Verbose -Message 'Deploying the AllowMicrosoftPlusBlockRules.xml policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy "$PolicyID.cip" -json | Out-Null
            }

            Write-Verbose -Message 'Displaying the output'
            Write-ColorfulText -Color MintGreen -InputText 'PolicyFile = AllowMicrosoftPlusBlockRules.xml'
            Write-ColorfulText -Color MintGreen -InputText "BinaryFile = $PolicyID.cip"

            # Copy the result to the User Config directory at the end
            Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force

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
            .PARAMETER Deploy
                Indicates that the function will deploy the DefaultWindowsPlusBlockRules policy
            #>
            [CmdletBinding()]
            param (
                [System.Management.Automation.SwitchParameter]$Deploy
            )

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 4 : 3
            [System.UInt16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Getting the recommended block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Getting the latest Microsoft recommended block rules'
            Push-Location -Path $StagingArea
            Get-BlockRulesMeta 6> $null
            Pop-Location

            [System.IO.FileInfo]$BaseTemplatePath = Join-Path -Path $StagingArea -ChildPath 'DefaultWindows_Enforced.xml'
            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DefaultWindowsPlusBlockRules.xml'

            Write-Verbose -Message 'Copying the DefaultWindows_Enforced.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination $BaseTemplatePath -Force

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Determining whether to include PowerShell core' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Scan PowerShell core directory (if installed using MSI only, because Microsoft Store installed version doesn't need to be allowed manually) and allow its files in the Default Windows base policy so that module can still be used once it's been deployed
            if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                Write-ColorfulText -Color Lavender -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                Write-Verbose -Message 'Merging the policy files to create the final DefaultWindowsPlusBlockRules.xml policy'
                Merge-CIPolicy -PolicyPaths $BaseTemplatePath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml'), (Join-Path -Path $StagingArea -ChildPath 'Microsoft recommended block rules.xml') -OutputFilePath $FinalPolicyPath | Out-Null
            }
            else {
                Write-Verbose -Message 'Merging the policy files to create the final DefaultWindowsPlusBlockRules.xml policy'
                Merge-CIPolicy -PolicyPaths $BaseTemplatePath, (Join-Path -Path $StagingArea -ChildPath 'Microsoft recommended block rules.xml') -OutputFilePath $FinalPolicyPath | Out-Null
            }

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Configuring policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and setting a name'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -PolicyName "Default Windows Plus Block Rules - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalPolicyPath -Version '1.0.0.0'

            Edit-CiPolicyRuleOptions -Action Base -XMLFile $FinalPolicyPath

            if ($TestMode -and $MakeDefaultWindowsWithBlockRules) {
                Write-Verbose -Message 'Setting "Boot Audit on Failure" and "Advanced Boot Options Menu" policy rule options because TestMode parameter was used'
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath $FinalPolicyPath -Option $_ }
            }

            if ($RequireEVSigners -and $MakeDefaultWindowsWithBlockRules) {
                Write-Verbose -Message 'Setting "Required:EV Signers" policy rule option because RequireEVSigners parameter was used'
                Set-RuleOption -FilePath $FinalPolicyPath -Option 8
            }

            if ($Deploy -and $MakeDefaultWindowsWithBlockRules) {

                $CurrentStep++
                Write-Progress -Id 7 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy file to .CIP binary'
                ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") | Out-Null

                Write-Verbose -Message 'Deploying the policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") -json | Out-Null
            }

            Write-Verbose -Message 'Displaying the output'
            Write-ColorfulText -Color MintGreen -InputText 'PolicyFile = DefaultWindowsPlusBlockRules.xml'
            Write-ColorfulText -Color MintGreen -InputText "BinaryFile = $PolicyID.cip"

            # Copy the result to the User Config directory at the end
            Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force

            Write-Progress -Id 7 -Activity 'Complete.' -Completed
        }

        Function Deploy-LatestBlockRules {
            <#
            .SYNOPSIS
                A helper function that downloads the latest Microsoft recommended block rules
                and deploys it as a standalone WDAC base policy on the system.
                The deployed policy contains the 2 Allow All rules so it acts as a blocklist.
            .INPUTS
                None. You cannot pipe objects to this function.
            .OUTPUTS
                System.String
            #>
            [CmdletBinding()]
            param()

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = 3
            [System.UInt16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Downloading the latest block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Downloading the latest Microsoft recommended block rules'
            [System.String]$MSFTRecommendedBlockRulesAsString = (Invoke-WebRequest -Uri $MSFTRecommendedBlockRulesURL -ProgressAction SilentlyContinue).Content

            # Load the Block Rules as XML into a variable after extracting them from the markdown string
            [System.Xml.XmlDocument]$BlockRulesXML = ($MSFTRecommendedBlockRulesAsString -replace "(?s).*``````xml(.*)``````.*", '$1').Trim()

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath 'Microsoft recommended block rules.xml'

            # Save the XML content to a file
            $BlockRulesXML.Save($FinalPolicyPath)

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Edit-CiPolicyRuleOptions -Action Base -XMLFile $FinalPolicyPath

            Write-Verbose -Message 'Resetting the policy ID and saving it to a variable'
            [System.String]$PolicyID = (Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -ResetPolicyID).Substring(11)

            Write-Verbose -Message 'Assigning a name to the policy'
            Set-CIPolicyIdInfo -PolicyName "Microsoft Windows User Mode Policy - Enforced - $(Get-Date -Format 'MM-dd-yyyy')" -FilePath '.\Microsoft recommended block rules.xml'

            Write-Verbose -Message 'Converting the policy file to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") | Out-Null

            $CurrentStep++
            Write-Progress -Id 0 -Activity 'Deploying the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the Microsoft recommended block rules policy'
            &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") -json | Out-Null

            Write-ColorfulText -Color Lavender -InputText 'The Microsoft recommended block rules policy has been deployed in enforced mode.'

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
            [OutputType([System.Void])]
            param()

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = 1
            [System.UInt16]$CurrentStep = 0

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
            [OutputType([System.Void])]
            param (
                [System.Management.Automation.SwitchParameter]$Deploy
            )

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 3 : 2
            [System.UInt16]$CurrentStep = 0

            if ($PrepMSFTOnlyAudit -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            $CurrentStep++
            Write-Progress -Id 5 -Activity 'Creating the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath 'AllowMicrosoft.xml'

            Write-Verbose -Message 'Copying AllowMicrosoft.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $FinalPolicyPath -Force

            Write-Verbose -Message 'Enabling Audit mode and disabling script enforcement'
            3, 11 | ForEach-Object -Process { Set-RuleOption -FilePath $FinalPolicyPath -Option $_ }

            $CurrentStep++
            Write-Progress -Id 5 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the Policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Assigning "PrepMSFTOnlyAudit" as the policy name'
            Set-CIPolicyIdInfo -PolicyName 'PrepMSFTOnlyAudit' -FilePath $FinalPolicyPath

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 5 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy to .CIP Binary'
                ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") | Out-Null

                Write-Verbose -Message 'Deploying the policy on the system'
                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") -json | Out-Null
                Write-ColorfulText -Color HotPink -InputText 'The default AllowMicrosoft policy has been deployed in Audit mode. No reboot required.'
            }
            else {
                Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force
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
            [OutputType([System.Void])]
            param (
                [System.Management.Automation.SwitchParameter]$Deploy
            )

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 4 : 3
            [System.UInt16]$CurrentStep = 0

            if ($PrepDefaultWindowsAudit -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            $CurrentStep++
            Write-Progress -Id 8 -Activity 'Fetching the policy template' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DefaultWindows_Audit.xml'

            Write-Verbose -Message 'Copying DefaultWindows_Audit.xml from Windows directory to the current working directory'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml' -Destination $FinalPolicyPath -Force

            $CurrentStep++
            Write-Progress -Id 8 -Activity 'Determining whether to include PowerShell core' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Making Sure neither PowerShell core (Installed using MSI because Microsoft Store installed version is automatically allowed) nor WDACConfig module files are added to the Supplemental policy created by -MakePolicyFromAuditLogs parameter
            # by adding them first to the deployed Default Windows policy in Audit mode. Because WDACConfig module files don't need to be allowed to run since they are *.ps1 and .*psm1 files
            # And PowerShell core files will be added to the DefaultWindows Base policy anyway
            if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {

                Write-Verbose -Message 'Scanning PowerShell core directory and creating a policy file'
                New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                Write-Verbose -Message 'Scanning WDACConfig module directory and creating a policy file'
                New-CIPolicy -ScanPath "$ModuleRootPath" -Level hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath (Join-Path -Path $StagingArea -ChildPath 'WDACConfigModule.xml')

                Write-Verbose -Message 'Merging the policy files for PowerShell core and WDACConfig module with the DefaultWindows_Audit.xml policy file'
                Merge-CIPolicy -PolicyPaths $FinalPolicyPath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml'), (Join-Path -Path $StagingArea -ChildPath 'WDACConfigModule.xml') -OutputFilePath (Join-Path -Path $StagingArea -ChildPath 'DefaultWindows_Audit_temp.xml') | Out-Null

                Write-Verbose -Message 'Renaming DefaultWindows_Audit_temp.xml to DefaultWindows_Audit.xml'
                Move-Item -Path (Join-Path -Path $StagingArea -ChildPath 'DefaultWindows_Audit_temp.xml') -Destination $FinalPolicyPath -Force
            }

            $CurrentStep++
            Write-Progress -Id 8 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Enabling Audit mode and disabling script enforcement'
            3, 11 | ForEach-Object -Process { Set-RuleOption -FilePath $FinalPolicyPath -Option $_ }

            Write-Verbose -Message 'Resetting the Policy ID'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Write-Verbose -Message 'Assigning "PrepDefaultWindowsAudit" as the policy name'
            Set-CIPolicyIdInfo -PolicyName 'PrepDefaultWindows' -FilePath $FinalPolicyPath

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 8 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy to .CIP Binary'
                ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") | Out-Null

                Write-Verbose -Message 'Deploying the policy on the system'
                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") -json | Out-Null

                Write-ColorfulText -Color Lavender -InputText 'The defaultWindows policy has been deployed in Audit mode. No reboot required.'
            }
            else {
                Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force
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
            [System.UInt16]$TotalSteps = 4
            [System.UInt16]$CurrentStep = 0

            if ($MakePolicyFromAuditLogs -and $LogSize) {
                Write-Verbose -Message 'Changing the Log size of Code Integrity Operational event log'
                Set-LogSize -LogSize $LogSize
            }

            #Region Base-Policy-Processing
            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Creating the base policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            switch ($BasePolicyType) {
                'Allow Microsoft Base' {
                    Write-Verbose -Message 'Creating Allow Microsoft Base policy'

                    Push-Location -Path $StagingArea
                    Build-AllowMSFTWithBlockRules 6> $null
                    Pop-Location

                    # Base policy path definition
                    [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath 'AllowMicrosoftPlusBlockRules.xml'

                    $Xml = [System.Xml.XmlDocument](Get-Content -Path $FinalPolicyPath)
                    [System.String]$BasePolicyID = $Xml.SiPolicy.PolicyID
                }
                'Default Windows Base' {
                    Write-Verbose -Message 'Creating Default Windows Base policy'

                    Push-Location -Path $StagingArea
                    Build-DefaultWindowsWithBlockRules 6> $null
                    Pop-Location

                    # Base policy path definition
                    [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath 'DefaultWindowsPlusBlockRules.xml'

                    $Xml = [System.Xml.XmlDocument](Get-Content -Path $FinalPolicyPath)
                    [System.String]$BasePolicyID = $Xml.SiPolicy.PolicyID
                }
            }

            if ($TestMode -and $MakePolicyFromAuditLogs) {
                Write-Verbose -Message 'Setting "Boot Audit on Failure" and "Advanced Boot Options Menu" policy rule options because TestMode parameter was used'
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath $FinalPolicyPath -Option $_ }
            }

            if ($RequireEVSigners -and $MakePolicyFromAuditLogs) {
                Write-Verbose -Message 'Setting "Required:EV Signers" policy rule option because RequireEVSigners parameter was used'
                Set-RuleOption -FilePath $FinalPolicyPath -Option 8
            }
            #Endregion Base-Policy-Processing

            #Region Supplemental-Policy-Processing
            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Scanning the event logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Audits policy path definition
            [System.IO.FileInfo]$PolicyFromAuditsPath = Join-Path $StagingArea -ChildPath 'AuditLogsPolicy_NoDeletedFiles.xml'

            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                FilePath               = $PolicyFromAuditsPath
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

            # Supplemental policy path definition
            [System.IO.FileInfo]$FinalSupplementalPath = Join-Path -Path $StagingArea -ChildPath 'SupplementalPolicy.xml'

            if (!$NoDeletedFiles) {
                # Get the hashes of the files no longer available on the disk
                $DeletedFileHashesArray = Receive-CodeIntegrityLogs -PostProcessing OnlyDeleted
            }
            # run the following only if there are any event logs for files no longer on the disk and if -NoDeletedFiles switch parameter wasn't used
            if ($DeletedFileHashesArray -and !$NoDeletedFiles) {

                # Save the the File Rules and File Rule Refs to the Out-File FileRulesAndFileRefs.txt in the current working directory
                    (Get-FileRules -HashesArray $DeletedFileHashesArray) + (Get-RuleRefs -HashesArray $DeletedFileHashesArray) | Out-File -FilePath (Join-Path -Path $StagingArea -ChildPath 'FileRulesAndFileRefs.txt') -Force

                # Put the Rules and RulesRefs in an empty policy file
                New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $DeletedFileHashesArray) -RuleRefsContent (Get-RuleRefs -HashesArray $DeletedFileHashesArray) | Out-File -FilePath (Join-Path -Path $StagingArea -ChildPath 'DeletedFilesHashes.xml') -Force

                # Merge the policy file we created at first using Event Viewer logs, with the policy file we created for Hash of the files no longer available on the disk
                Merge-CIPolicy -PolicyPaths $PolicyFromAuditsPath, (Join-Path -Path $StagingArea -ChildPath 'DeletedFilesHashes.xml') -OutputFilePath $FinalSupplementalPath | Out-Null
            }
            # do this only if there are no event logs detected with files no longer on the disk, so we use the policy file created earlier using Audit even logs
            else {
                Move-Item -Path $PolicyFromAuditsPath -Destination $FinalSupplementalPath -Force
            }

            Write-Verbose -Message 'Setting the version for SupplementalPolicy.xml policy to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalSupplementalPath -Version '1.0.0.0'

            # Convert the SupplementalPolicy.xml policy file from base policy to supplemental policy of our base policy
            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Adjusting the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Convert the SupplementalPolicy.xml policy file from base policy to supplemental policy of our base policy'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -PolicyName "Supplemental Policy made from Audit Event Logs on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $FinalPolicyPath
            [System.String]$PolicyID = $PolicyID.Substring(11)

            Edit-CiPolicyRuleOptions -Action Supplemental -XMLFile $FinalSupplementalPath

            $CurrentStep++
            Write-Progress -Id 4 -Activity 'Generating the CIP files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Converting SupplementalPolicy.xml policy to .CIP binary'
            ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") | Out-Null
            #Endregion Supplemental-Policy-Processing

            Write-ColorfulText -Color MintGreen -InputText "BasePolicyFile = $FinalPolicyPath"
            Write-ColorfulText -Color MintGreen -InputText "BasePolicyGUID = $BasePolicyID"

            Write-ColorfulText -Color MintGreen -InputText 'SupplementalPolicyFile = SupplementalPolicy.xml'
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $PolicyID"

            if ($Deploy -and $MakePolicyFromAuditLogs) {
                Write-Verbose -Message 'Deploying the Base policy and Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$BasePolicyID.cip") -json | Out-Null
                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$PolicyID.cip") -json | Out-Null

                Write-ColorfulText -Color Pink -InputText 'Base policy and Supplemental Policies deployed and activated.'

                Write-Verbose -Message 'Getting the correct Prep mode Audit policy ID to remove from the system'
                switch ($BasePolicyType) {
                    'Allow Microsoft Base' {
                        Write-Verbose -Message 'Going to remove the AllowMicrosoft policy from the system because Allow Microsoft Base was used'
                        [System.String]$IDToRemove = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.FriendlyName -eq 'PrepMSFTOnlyAudit' }).PolicyID
                    }
                    'Default Windows Base' {
                        Write-Verbose -Message 'Going to remove the DefaultWindows policy from the system because Default Windows Base was used'
                        [System.String]$IDToRemove = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.FriendlyName -eq 'PrepDefaultWindows' }).PolicyID
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
            .PARAMETER Deploy
                A switch parameter that deploys the policy on the system if used
            #>
            [CmdletBinding()]
            param (
                [System.Management.Automation.SwitchParameter]$Deploy
            )

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 5 : 3
            [System.UInt16]$CurrentStep = 0

            # Delete any policy with the same name in the current working directory
            Remove-Item -Path 'SignedAndReputable.xml' -Force -ErrorAction SilentlyContinue

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Creating AllowMicrosoftPlusBlockRules policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Calling Build-AllowMSFTWithBlockRules function to create AllowMicrosoftPlusBlockRules.xml policy'

            # Redirecting the function's information Stream to $null because Write-Host
            # Used by Write-ColorfulText outputs to both information stream and host console
            Push-Location -Path $StagingArea
            Build-AllowMSFTWithBlockRules 6> $null
            Pop-Location

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

            if ($Deploy -and $MakeLightPolicy) {

                $CurrentStep++
                Write-Progress -Id 6 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting SignedAndReputable.xml policy to .CIP binary'
                ConvertFrom-CIPolicy -XmlFilePath .\SignedAndReputable.xml -BinaryFilePath "$BasePolicyID.cip" | Out-Null

                $CurrentStep++
                Write-Progress -Id 6 -Activity 'Configuring Windows Services' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Configuring required services for ISG authorization'
                Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -NoNewWindow
                Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -NoNewWindow

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
        Try {
            switch ($true) {
                # Deploy the latest block rules if 'New-WDACConfig -GetBlockRules -Deploy' is passed
                { $GetBlockRules -and $Deploy } { Deploy-LatestBlockRules ; break }
                # Get the latest block rules if 'New-WDACConfig -GetBlockRules' is passed
                $GetBlockRules { Get-BlockRulesMeta ; break }
                # Get the latest driver block rules and only Deploy them if New-WDACConfig -GetDriverBlockRules was called with -Deploy parameter
                $GetDriverBlockRules { Get-DriverBlockRules -Deploy:$Deploy ; break }
                $SetAutoUpdateDriverBlockRules { Set-AutoUpdateDriverBlockRules ; break }
                $MakeAllowMSFTWithBlockRules { Build-AllowMSFTWithBlockRules -Deploy:$Deploy ; break }
                $MakePolicyFromAuditLogs { Build-PolicyFromAuditLogs ; break }
                $PrepMSFTOnlyAudit { Build-MSFTOnlyAudit ; break }
                $MakeLightPolicy { Build-LightPolicy -Deploy:$Deploy ; break }
                $MakeDefaultWindowsWithBlockRules { Build-DefaultWindowsWithBlockRules -Deploy:$Deploy; break }
                $PrepDefaultWindowsAudit { Build-DefaultWindowsAudit ; break }
                default { Write-Warning -Message 'None of the main parameters were selected.'; break }
            }
        }
        Finally {
            if (-NOT $Debug) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
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
    System.UInt64
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

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA0S4zAUuQXZc4Y
# n2aA77/RAVXP/5/zkHLW3mrjHyIyzKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg/Mh7oxkkZmWcSAsgj1FH1f++qnX/tRNyRnEIEDyWJBIwDQYJKoZIhvcNAQEB
# BQAEggIAYhAaBSQWFrEEVcxydTRAvnFRM6mkfbnLtPzmv5KVqZ1kiYs5Pgd1t9wz
# l3FCxj+lJ82yrC4SSn+IIw9L7bsLI1asfyIMS0k4EyVQRfXpxsvMNIHAnBR7kJIx
# 2szgQvXv8tsqhTXkeNmD/Wp3FaTNh73VhtzsbgY2m++8yLLB34AFp6BcKLYGLpz+
# vkchLunl3R6D5nEJrZfyWSS8NGVn9rBYIMYsKIry5FqaAfgn2sDR1dB23M2Fkw7y
# Ul5O+5PZEvueOWpFa/QDwQr4w54jOIfbTgfDNix/8UhpIuLxt5kmo78+KJEpzLCo
# iu6fmhU+Y7Q2QJqTMPOt3d6i3KDCP/2EdYjIgMgtJ+IWOllcYkhNAjEWlsvDG2t8
# ojW2rTxCE30jluZUXBPcNGkGLlrRMJ0ASxphxdWGsxobrRDwLQmjoP5OTaZOSQuq
# LWF0Vvg6Cgjijrgtq7sAKo2q1ULKkeDVMq4Cv7eI1MB0hKLd6mEE6QB2G1jPECC/
# AEI7JcwyBfHIHJQqeO8ZJ/6TOZAj8tQvWvR3SI8gLWWKJKNsswdsMIRbctJ33VIv
# +bEDmVm9f+pLBfm/XdbU/ZY0uzA89jakQ+YSgANmZ39hUbqc1vnUX2Y9aLlFyqxy
# WuVtaweqUI1TO8Por3cxnMSgBS6t6GA/8lV4SzxnLAU+nIwSN5E=
# SIG # End signature block
