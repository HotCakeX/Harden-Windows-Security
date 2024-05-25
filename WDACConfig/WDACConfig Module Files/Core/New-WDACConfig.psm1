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
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\Shared\Set-LogSize.psm1",
            "$ModuleRootPath\Shared\New-StagingArea.psm1",
            "$ModuleRootPath\Shared\Edit-GUIDs.psm1"
        )

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'New-WDACConfig'

        # Define the varaibles in the function scope for the dynamic parameters
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
                &'C:\Windows\System32\CiTool.exe' --refresh -json | Out-Null

                Write-ColorfulText -Color Pink -InputText 'SiPolicy.p7b has been deployed and policies refreshed.'

                Write-Verbose -Message "Displaying extra info about the $Name"
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
            }
            else {
                $CurrentStep++
                Write-Progress -Id 1 -Activity "Downloading the $Name" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Download the markdown page from GitHub containing the latest Microsoft recommended driver block rules
                [System.String]$MSFTDriverBlockRulesAsString = (Invoke-WebRequest -Uri $MSFTRecommendedDriverBlockRulesURL -ProgressAction SilentlyContinue).Content

                $CurrentStep++
                Write-Progress -Id 1 -Activity "Removing the 'Allow all rules' from the policy" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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

                [System.IO.FileInfo]$XMLPath = Join-Path -Path $StagingArea -ChildPath "$Name.xml"

                # Save the modified XML content to a file
                $DriverBlockRulesXML.Save($XMLPath)

                $CurrentStep++
                Write-Progress -Id 1 -Activity 'Configuring the policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Set-CiRuleOptions -FilePath $XMLPath -RulesToRemove 'Enabled:Audit Mode'

                Write-Verbose -Message "Displaying extra info about the $Name"
                Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK

                # Copy the result to the User Config directory at the end
                Copy-Item -Path $XMLPath -Destination $UserConfigDir -Force

                &$WriteFinalOutput $XMLPath
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
            if ($Audit) { Set-LogSize -LogSize:$LogSize }
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
            Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID | Out-Null

            Write-Verbose -Message 'Setting policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalPolicyPath -Version '1.0.0.0'

            Set-CiRuleOptions -FilePath $FinalPolicyPath -Template Base -TestMode:$TestMode -RequireEVSigners:$RequireEVSigners -ScriptEnforcement:$EnableScriptEnforcement -EnableAuditMode:$Audit

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 3 -Activity 'Creating CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy file to .CIP binary'
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                Write-Verbose -Message "Deploying the $Name policy"
                &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json | Out-Null
            }
            Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force
            &$WriteFinalOutput $FinalPolicyPath

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
            if ($Audit) { Set-LogSize -LogSize:$LogSize }
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
                Write-ColorfulText -Color Lavender -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                Write-Verbose -Message "Merging the policy files to create the final $Name.xml policy"
                Merge-CIPolicy -PolicyPaths $FinalPolicyPath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml') -OutputFilePath $FinalPolicyPath | Out-Null
            }

            $CurrentStep++
            Write-Progress -Id 7 -Activity 'Configuring policy settings' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Resetting the policy ID and assigning policy name'
            Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID | Out-Null

            Write-Verbose -Message 'Setting the policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $FinalPolicyPath -Version '1.0.0.0'

            Set-CiRuleOptions -FilePath $FinalPolicyPath -Template Base -TestMode:$TestMode -RequireEVSigners:$RequireEVSigners -ScriptEnforcement:$EnableScriptEnforcement -EnableAuditMode:$Audit

            if ($Deploy) {
                $CurrentStep++
                Write-Progress -Id 7 -Activity 'Creating the CIP file' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy file to .CIP binary'
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                Write-Verbose -Message 'Deploying the policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json | Out-Null
            }

            # Copy the result to the User Config directory at the end
            Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force
            &$WriteFinalOutput $FinalPolicyPath

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
                [System.String]$MSFTRecommendedBlockRulesAsString = (Invoke-WebRequest -Uri $MSFTRecommendedBlockRulesURL -ProgressAction SilentlyContinue).Content

                # Load the Block Rules into a variable after extracting them from the markdown string
                [System.String]$XMLContent = ($MSFTRecommendedBlockRulesAsString -replace "(?s).*``````xml(.*)``````.*", '$1').Trim()

                Set-Content -Value $XMLContent -LiteralPath $FinalPolicyPath -Force

                Set-CiRuleOptions -FilePath $FinalPolicyPath -RulesToRemove 'Enabled:Audit Mode' -RulesToAdd 'Enabled:Update Policy No Reboot'

                Write-Verbose -Message 'Assigning policy name and resetting policy ID'
                Set-CIPolicyIdInfo -ResetPolicyID -FilePath $FinalPolicyPath -PolicyName $Name | Out-Null

                if ($Deploy) {

                    Write-Verbose -Message "Checking if the $Name policy is already deployed"
                    [System.String]$CurrentlyDeployedBlockRulesGUID = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) -and ($_.FriendlyName -eq $Name) }).PolicyID

                    if (-NOT ([System.String]::IsNullOrWhiteSpace($CurrentlyDeployedBlockRulesGUID))) {
                        Write-Verbose -Message "$Name policy is already deployed, updating it using the same GUID."
                        Edit-GUIDs -PolicyIDInput $CurrentlyDeployedBlockRulesGUID -PolicyFilePathInput $FinalPolicyPath
                    }

                    [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $FinalPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$Name.cip")

                    Write-Verbose -Message "Deploying the $Name policy"
                    &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json | Out-Null
                }
                else {
                    Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force
                    &$WriteFinalOutput $FinalPolicyPath
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
            if ($Audit) { Set-LogSize -LogSize:$LogSize }
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
            Set-CIPolicyIdInfo -FilePath $FinalPolicyPath -ResetPolicyID -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')" | Out-Null

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
                &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json | Out-Null
            }

            Copy-Item -Path $FinalPolicyPath -Destination $UserConfigDir -Force
            &$WriteFinalOutput $FinalPolicyPath

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

                Write-ColorfulText -Color Lavender -InputText "The document containing the drivers block list on GitHub was last updated on $Date"
                [System.String]$MicrosoftRecommendedDriverBlockRules = (Invoke-WebRequest -Uri $MSFTRecommendedDriverBlockRulesURL -ProgressAction SilentlyContinue).Content
                $MicrosoftRecommendedDriverBlockRules -match '<VersionEx>(.*)</VersionEx>' | Out-Null
                Write-ColorfulText -Color Pink -InputText "The current version of Microsoft recommended drivers block list is $($Matches[1])"
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

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA7mxmekAgCzE1L
# F36s5mtrWDR2nzWfTWXIf5qu7yTfBqCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgO3B2MnTqyfRq8ZMaZV/qaQSeNCb98wO+gWAMPcVOFqUwDQYJKoZIhvcNAQEB
# BQAEggIAJhIVPH4vQmgT4LEgjiSrkEzGw6bI2OJfFCTA2oXDkfDsaQAC8V4CYoap
# VturR7xI8Jcr9Yxf1y9wwEHLpnRwdXzRmNemYSGq4FSg5IUAb3ZtZjLNv5fFTO92
# SPwS8jPZiEzlE2r0pV3kfoNc6+M9dnlPWjROskHTqHEnPRbzlNbLLWlp9av06l+G
# BDJKKmjPD+9I9Mh2FsUDFcNLzUcTQJ1FO4NvOr1LMJ6awBWrIhb7VivnXSHkam5m
# 3h/rf67ceEqt3OUbODODqk6mcT5Rer+EJFmE4UvnXCzsPq+U8DjUR0rr2ECqU3ME
# hgnkKByKvwKAEIYrzrh0FrFJuOBZMDW6+s2kYlBUJkjnjYhoYM/zb5HOLINKNJtx
# gxQkv4NTABMHePaKuDmzelt2/cbHaEdIj0yV5opcoX/5bGVTWPcE599l5lcTabiE
# 7aemPh7oB3uOquO7qHx8MYMj/lYgYn4+mIvFMkkkPyzbHsUUwd72d7WW5OKxtP4K
# IbgchqbhbwVonYERXPwLl9bn5oo/Yg4u1CUDV4bUqIWzYUgm414KFa1ImwbEg0k1
# X6/fuzjSHKa8V/vmZiA4l2GGzQvey7VNu7k0vQX1n7nw1p3MIwqSr9ciJJN6aC+C
# X20RHt3NA1pdVmd69W2KoWnlJMt6OA8ysNWV3owl3f1DhWTQJUY=
# SIG # End signature block
