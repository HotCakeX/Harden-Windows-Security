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
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        [System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Update-Self.psm1"

        if ([WDACConfig.GlobalVars]::ConfigCIBootstrap -eq $false) {
            Invoke-MockConfigCIBootstrap
            [WDACConfig.GlobalVars]::ConfigCIBootstrap = $true
        }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('New-WDACConfig')

        # Define the variables in the function scope for the dynamic parameters
        New-Variable -Name 'LogSize' -Value $PSBoundParameters['LogSize'] -Force

        Function Get-DriverBlockRules {
            <#
            .SYNOPSIS
                Gets the latest Microsoft Recommended Driver Block rules
                1) can deploy them
                2) set them to be auto-updated via task scheduler
                3) create XML file with the rules and remove the allow all rules from the policy
            #>

            if ($AutoUpdate) {

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 1
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 2 -Activity 'Setting up the Scheduled task' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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

                Return
            }

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = 3
            [System.UInt16]$CurrentStep = 0

            [System.String]$Name = 'Microsoft Recommended Driver Block Rules'

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 1 -Activity "Downloading the $Name" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message "Downloading the $Name archive"
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
                $null = &'C:\Windows\System32\CiTool.exe' --refresh -json

                Write-ColorfulTextWDACConfig -Color Pink -InputText 'SiPolicy.p7b has been deployed and policies refreshed.'

                Write-Verbose -Message "Displaying extra info about the $Name"
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
            }
            else {
                $CurrentStep++
                Write-Progress -Id 1 -Activity "Downloading the $Name" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Download the markdown page from GitHub containing the latest Microsoft recommended driver block rules
                [System.String]$MSFTDriverBlockRulesAsString = (Invoke-WebRequest -Uri ([WDACConfig.GlobalVars]::MSFTRecommendedDriverBlockRulesURL) -ProgressAction SilentlyContinue).Content

                $CurrentStep++
                Write-Progress -Id 1 -Activity "Removing the 'Allow all rules' from the policy" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Load the Driver Block Rules as XML into a variable after extracting them from the markdown string
                [System.Xml.XmlDocument]$DriverBlockRulesXML = ($MSFTDriverBlockRulesAsString -replace "(?s).*``````xml(.*)``````.*", '$1').Trim()

                # Get the SiPolicy node
                [System.Xml.XmlElement]$SiPolicyNode = $DriverBlockRulesXML.SiPolicy

                Write-Verbose -Message "Removing the 'Allow all rules' from the policy"

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
                        [System.Void]$ParentNode.RemoveChild($Node)
                    }

                    # If the parent node only has one child node then replace the parent node with an empty node
                    else {
                        # Create a new node with the same name and namespace as the parent node
                        [System.Xml.XmlElement]$NewNode = $DriverBlockRulesXML.CreateElement($ParentNode.Name, $ParentNode.NamespaceURI)
                        # Replace the parent node with the new node
                        [System.Void]$ParentNode.ParentNode.ReplaceChild($NewNode, $ParentNode)

                        # Check if the new node has any sibling nodes, if not then replace its parent node with an empty node
                        # We do this because the built-in PowerShell cmdlets would throw errors if empty <FileRulesRef /> exists inside <ProductSigners> node
                        if ($null -eq $NewNode.PreviousSibling -and $null -eq $NewNode.NextSibling) {

                            # Get the grandparent node of the new node
                            [System.Xml.XmlElement]$GrandParentNode = $NewNode.ParentNode

                            # Create a new node with the same name and namespace as the grandparent node
                            [System.Xml.XmlElement]$NewGrandNode = $DriverBlockRulesXML.CreateElement($GrandParentNode.Name, $GrandParentNode.NamespaceURI)

                            # Replace the grandparent node with the new node
                            [System.Void]$GrandParentNode.ParentNode.ReplaceChild($NewGrandNode, $GrandParentNode)
                        }
                    }
                }

                [System.IO.FileInfo]$XMLPath = Join-Path -Path $StagingArea -ChildPath "$Name.xml"

                # Save the modified XML content to a file
                $DriverBlockRulesXML.Save($XMLPath)

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Set-CiRuleOptions -FilePath $XMLPath -RulesToRemove 'Enabled:Audit Mode'

                Write-Verbose -Message "Displaying extra info about the $Name"
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK

                # Copy the result to the User Config directory at the end
                Copy-Item -Path $XMLPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                Write-FinalOutput -Paths $XMLPath
            }
            Write-Progress -Id 1 -Activity 'Complete.' -Completed
        }
        Function Build-AllowMSFT {
            <#
            .SYNOPSIS
                Creates a base policy based on the AllowMicrosoft template.
            .INPUTS
                None
            .OUTPUTS
                System.String
            #>
            if ($Audit) { [WDACConfig.EventLogUtility]::SetLogSize($LogSize ?? 0) }
            [System.String]$Name = $Audit ? 'AllowMicrosoftAudit' : 'AllowMicrosoft'

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 3 : 2
            [System.UInt16]$CurrentStep = 0

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath "$Name.xml"

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Getting the recommended block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Get-BlockRules

            Write-Verbose -Message 'Copying the AllowMicrosoft.xml from Windows directory to the Staging Area'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $FinalPolicyPath -Force

            $CurrentStep++
            Write-Progress -Id 3 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and assigning policy name'
            $null = Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID

            Write-Verbose -Message 'Setting policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalPolicyPath -Version '1.0.0.0'

            Set-CiRuleOptions -FilePath $FinalPolicyPath -Template Base -TestMode:$TestMode -RequireEVSigners:$RequireEVSigners -ScriptEnforcement:$EnableScriptEnforcement -EnableAuditMode:$Audit

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 3 -Activity 'Creating CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy file to .CIP binary'
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                Write-Verbose -Message "Deploying the $Name policy"
                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json
            }
            Copy-Item -Path $FinalPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            Write-FinalOutput -Paths $FinalPolicyPath

            Write-Progress -Id 3 -Activity 'Complete' -Completed
        }
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

            Get-BlockRules

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath "$Name.xml"

            Write-Verbose -Message 'Copying the DefaultWindows_Enforced.xml from Windows directory to the Staging Area'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination $FinalPolicyPath -Force

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Determining whether to include PowerShell core' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Scan PowerShell core directory (if installed using MSI only, because Microsoft Store installed version doesn't need to be allowed manually) and allow its files in the Default Windows base policy so that module can still be used once it's been deployed
            if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                Write-ColorfulTextWDACConfig -Color Lavender -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                Write-Verbose -Message "Merging the policy files to create the final $Name.xml policy"
                $null = Merge-CIPolicy -PolicyPaths $FinalPolicyPath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml') -OutputFilePath $FinalPolicyPath
            }

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Configuring policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and assigning policy name'
            $null = Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID

            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalPolicyPath -Version '1.0.0.0'

            Set-CiRuleOptions -FilePath $FinalPolicyPath -Template Base -TestMode:$TestMode -RequireEVSigners:$RequireEVSigners -ScriptEnforcement:$EnableScriptEnforcement -EnableAuditMode:$Audit

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 7 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy file to .CIP binary'
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                Write-Verbose -Message 'Deploying the policy'
                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json
            }

            # Copy the result to the User Config directory at the end
            Copy-Item -Path $FinalPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            Write-FinalOutput -Paths $FinalPolicyPath

            Write-Progress -Id 7 -Activity 'Complete.' -Completed
        }
        Function Get-BlockRules {
            <#
            .SYNOPSIS
                Gets the latest Microsoft Recommended block rules for User Mode files, removes the audit mode policy rule option and sets HVCI to strict
                It generates a XML file compliant with CI Policies Schema.
            .OUTPUTS
                System.IO.FileInfo
            #>
            Begin {
                [System.String]$Name = 'Microsoft Windows Recommended User Mode BlockList'
                [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath "$Name.xml"
            }
            Process {
                Write-Verbose -Message "Getting the latest $Name from the official Microsoft GitHub repository"
                [System.String]$MSFTRecommendedBlockRulesAsString = (Invoke-WebRequest -Uri ([WDACConfig.GlobalVars]::MSFTRecommendedBlockRulesURL) -ProgressAction SilentlyContinue).Content

                # Load the Block Rules into a variable after extracting them from the markdown string
                [System.String]$XMLContent = ($MSFTRecommendedBlockRulesAsString -replace "(?s).*``````xml(.*)``````.*", '$1').Trim()

                Set-Content -Value $XMLContent -LiteralPath $FinalPolicyPath -Force

                Set-CiRuleOptions -FilePath $FinalPolicyPath -RulesToRemove 'Enabled:Audit Mode' -RulesToAdd 'Enabled:Update Policy No Reboot'

                Write-Verbose -Message 'Assigning policy name and resetting policy ID'
                $null = Set-CIPolicyIdInfo -ResetPolicyID -FilePath $FinalPolicyPath -PolicyName $Name

                if ($Deploy) {

                    Write-Verbose -Message "Checking if the $Name policy is already deployed"
                    [System.String]$CurrentlyDeployedBlockRulesGUID = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) -and ($_.FriendlyName -eq $Name) }).PolicyID

                    if (-NOT ([System.String]::IsNullOrWhiteSpace($CurrentlyDeployedBlockRulesGUID))) {
                        Write-Verbose -Message "$Name policy is already deployed, updating it using the same GUID."
                        [WDACConfig.PolicyEditor]::EditGUIDs($CurrentlyDeployedBlockRulesGUID, $FinalPolicyPath)
                    }

                    [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                    Write-Verbose -Message "Deploying the $Name policy"
                    $null = &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json
                }
                else {
                    Copy-Item -Path $FinalPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
                    Write-FinalOutput -Paths $FinalPolicyPath
                }
            }
        }
        Function Build-SignedAndReputable {
            <#
            .SYNOPSIS
                Creates SignedAndReputable WDAC policy which is based on AllowMicrosoft template policy.
                It uses ISG to authorize files with good reputation.
            .INPUTS
                None
            .OUTPUTS
                System.String
            #>
            if ($Audit) { [WDACConfig.EventLogUtility]::SetLogSize($LogSize ?? 0) }
            [System.String]$Name = $Audit ? 'SignedAndReputableAudit' : 'SignedAndReputable'

            # The total number of the main steps for the progress bar to render
            [System.UInt16]$TotalSteps = $Deploy ? 5 : 3
            [System.UInt16]$CurrentStep = 0

            [System.IO.FileInfo]$FinalPolicyPath = Join-Path -Path $StagingArea -ChildPath "$Name.xml"

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Getting the recommended block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Get-BlockRules

            Write-Verbose -Message 'Copying the AllowMicrosoft.xml from Windows directory to the Staging Area'
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $FinalPolicyPath -Force

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Configuring the policy rule options' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Set-CiRuleOptions -FilePath $FinalPolicyPath -Template BaseISG -TestMode:$TestMode -RequireEVSigners:$RequireEVSigners -ScriptEnforcement:$EnableScriptEnforcement -EnableAuditMode:$Audit

            $CurrentStep++
            Write-Progress -Id 6 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and assigning policy name'
            $null = Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -ResetPolicyID -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')"

            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalPolicyPath -Version '1.0.0.0'

            if ($Deploy) {

                $CurrentStep++
                Write-Progress -Id 6 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy to .CIP binary'
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                $CurrentStep++
                Write-Progress -Id 6 -Activity 'Configuring Windows Services' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Configuring required services for ISG authorization'
                Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -NoNewWindow
                Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -NoNewWindow

                Write-Verbose -Message 'Deploying the policy'
                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json
            }

            Copy-Item -Path $FinalPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            Write-FinalOutput -Paths $FinalPolicyPath

            Write-Progress -Id 6 -Activity 'Complete.' -Completed
        }

        # Script block that is used to supply extra information regarding Microsoft recommended driver block rules in commands that use them
        [System.Management.Automation.ScriptBlock]$DriversBlockListInfoGatheringSCRIPTBLOCK = {
            try {
                [System.String]$Owner = 'MicrosoftDocs'
                [System.String]$Repo = 'windows-itpro-docs'
                [System.String]$Path = 'windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md'

                [System.String]$ApiUrl = "https://api.github.com/repos/$Owner/$Repo/commits?path=$Path"
                [System.Object[]]$Response = Invoke-RestMethod -Uri $ApiUrl -ProgressAction SilentlyContinue
                [System.DateTime]$Date = $Response[0].commit.author.date

                Write-ColorfulTextWDACConfig -Color Lavender -InputText "The document containing the drivers block list on GitHub was last updated on $Date"
                [System.String]$MicrosoftRecommendedDriverBlockRules = (Invoke-WebRequest -Uri ([WDACConfig.GlobalVars]::MSFTRecommendedDriverBlockRulesURL) -ProgressAction SilentlyContinue).Content
                $null = $MicrosoftRecommendedDriverBlockRules -match '<VersionEx>(.*)</VersionEx>'
                Write-ColorfulTextWDACConfig -Color Pink -InputText "The current version of Microsoft recommended drivers block list is $($Matches[1])"
            }
            catch {
                Write-Error -ErrorAction Continue -Message $_
                Write-Error -ErrorAction Continue -Message 'Could not get additional information about the Microsoft recommended driver block list'
            }
        }

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }
    }

    process {
        Try {
            Switch ($PSCmdlet.ParameterSetName) {
                'PolicyType' {
                    Switch ($PSBoundParameters['PolicyType']) {
                        'DefaultWindows' { Build-DefaultWindows ; break }
                        'AllowMicrosoft' { Build-AllowMSFT ; break }
                        'SignedAndReputable' { Build-SignedAndReputable ; break }
                    }
                }
                'GetUserModeBlockRules' { Get-BlockRules ; break }
                'GetDriverBlockRules' { Get-DriverBlockRules ; break }
                default { Write-Warning -Message 'None of the main parameters were selected.'; break }
            }
        }
        catch {
            throw $_
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
