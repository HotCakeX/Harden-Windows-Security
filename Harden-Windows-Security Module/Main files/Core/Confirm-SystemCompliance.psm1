function Confirm-SystemCompliance {
    [CmdletBinding()]
    [OutputType([System.String], [System.Collections.Concurrent.ConcurrentDictionary[System.String, HardeningModule.IndividualResult[]]])]
    param (
        [ArgumentCompleter({
                # Get the current command and the already bound parameters
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                # Find all string constants in the AST
                $Existing = $CommandAst.FindAll(
                    # The predicate scriptblock to define the criteria for filtering the AST nodes
                    {
                        $Args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    },
                    # The recurse flag, whether to search nested scriptblocks or not.
                    $false
                ).Value

                foreach ($Item in [HardeningModule.ComplianceCategoriex]::new().GetValidValues()) {
                    # Check if the item is already selected
                    if ($Item -notin $Existing) {
                        # Return the item
                        $Item
                    }
                }

            })]
        [ValidateScript({
                if ($_ -notin [HardeningModule.ComplianceCategoriex]::new().GetValidValues()) { throw "Invalid Category Name: $_" }
                # Return true if everything is okay
                $true
            })]
        [System.String[]]$Categories,

        [parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$ExportToCSV,
        [parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$ShowAsObjectsOnly,
        [parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$DetailedDisplay,
        [parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Offline
    )
    begin {
        [HardeningModule.Initializer]::Initialize($VerbosePreference)

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$([HardeningModule.GlobalVars]::Path)\Shared\Update-self.psm1" -Force -Verbose:$false

        # Makes sure this cmdlet is invoked with Admin privileges
        if (-NOT ([HardeningModule.UserPrivCheck]::IsAdmin())) {
            Throw [System.Security.AccessControl.PrivilegeNotHeldException] 'Administrator'
        }

        if (-NOT $Offline) {
            Write-Verbose -Message 'Checking for updates...'
            Update-Self -InvocationStatement $MyInvocation.Statement
        }

        if ((Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false).OperatingSystemSKU -in '101', '100') {
            Write-Warning -Message 'The Windows Home edition has been detected, many features are unavailable in this edition.'
        }

        # The total number of the steps for the parent/main progress bar to render
        [System.UInt16]$TotalMainSteps = 2
        [System.UInt16]$CurrentMainStep = 0

        #Region Colors
        [System.Collections.Hashtable]$global:ColorsMap = @{
            Plum         = @{
                Code        = '221', '160', '221'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(221,160,221))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            Orchid       = @{
                Code        = '218', '112', '214'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(218,112,214))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            Fuchsia      = @{
                Code        = '255', '0', '255'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,0,255))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            MediumOrchid = @{
                Code        = '186', '85', '211'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(186,85,211))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            MediumPurple = @{
                Code        = '147', '112', '219'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(147,112,219))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            BlueViolet   = @{
                Code        = '138', '43', '226'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(138,43,226))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            AndroidGreen = @{
                Code        = '176', '191', '26'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(176,191,26))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            Pink         = @{
                Code        = '255', '192', '203'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,192,203))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            HotPink      = @{
                Code        = '255', '105', '180'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,105,180))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            DeepPink     = @{
                Code        = '255', '20', '147'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,20,147))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            MintGreen    = @{
                Code        = '152', '255', '152'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            Orange       = @{
                Code        = '255', '165', '0'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,165,0))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            SkyBlue      = @{
                Code        = '135', '206', '235'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(135,206,235))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
            Daffodil     = @{
                Code        = '255', '255', '49'
                ScriptBlock = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,255,49))$($PSStyle.Reverse)$($Args[0])$($PSStyle.Reset)" }
            }
        }

        # Defining a validate set class for the colors
        Class Colorsx : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Colorsx = @($global:ColorsMap.Keys)
                return [System.String[]]$Colorsx
            }
        }

        # An array of colors used in multiple places
        [System.Drawing.Color[]]$Global:Colors = @(
            [System.Drawing.Color]::SkyBlue,
            [System.Drawing.Color]::Pink,
            [System.Drawing.Color]::HotPink,
            [System.Drawing.Color]::Lavender,
            [System.Drawing.Color]::LightGreen,
            [System.Drawing.Color]::Coral,
            [System.Drawing.Color]::Plum,
            [System.Drawing.Color]::Gold
        )

        [System.Management.Automation.ScriptBlock]$WriteRainbow = {
            Param([System.String]$Text)
            $StringBuilder = New-Object -TypeName System.Text.StringBuilder
            for ($i = 0; $i -lt $Text.Length; $i++) {
                $Color = $Global:Colors[$i % $Global:Colors.Length]
                [System.Void]$StringBuilder.Append("$($PSStyle.Foreground.FromRGB($Color.R, $Color.G, $Color.B))$($Text[$i])$($PSStyle.Reset)")
            }
            Write-Output -InputObject $StringBuilder.ToString()
        }
        #Endregion Colors

        $PSStyle.Progress.Style = "$($PSStyle.Foreground.FromRGB(221, 160, 221))$($PSStyle.Blink)"
    }

    process {

        try {
            $CurrentMainStep++
            Write-Progress -Id 0 -Activity 'Gathering Security Policy Information' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

            # Get the security group policies
            $null = &"$env:SystemDrive\Windows\System32\Secedit.exe" /export /cfg ([HardeningModule.GlobalVars]::securityPolicyInfPath)

            # Storing the output of the ini file parsing function
            [HardeningModule.GlobalVars]::SystemSecurityPoliciesIniObject = [HardeningModule.IniFileConverter]::ConvertFromIniFile([HardeningModule.GlobalVars]::securityPolicyInfPath)

            # Process the SecurityPoliciesVerification.csv and save the output to the global variable HardeningModule.GlobalVars.SecurityPolicyRecords
            [HardeningModule.GlobalVars]::SecurityPolicyRecords = [HardeningModule.SecurityPolicyCsvProcessor]::ProcessSecurityPolicyCsvFile([System.IO.Path]::Combine([HardeningModule.GlobalVars]::path, 'Resources', 'SecurityPoliciesVerification.csv'))

            $CurrentMainStep++
            Write-Progress -Id 0 -Activity 'Verifying the security settings' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

            #Region Main-Functions
            Function Invoke-MicrosoftDefender {

                [System.Management.Automation.Job2]$script:MicrosoftDefenderJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {

                    Try {

                        $ErrorActionPreference = 'Stop'
                        $VerbosePreference = ([HardeningModule.GlobalVars]::VerbosePreference)

                        # A try-Catch-finally block to revert the changes being made to the Controlled Folder Access exclusions list
                        # Which is currently required for BCD NX value verification in the MicrosoftDefender category
                        [HardeningModule.ControlledFolderAccessHandler]::Start()

                        # Give the Defender internals time to process the updated exclusions list
                        Start-Sleep -Seconds '5'

                        $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                        [System.String]$CatName = 'MicrosoftDefender'

                        # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                        foreach ($Result in ([HardeningModule.CategoryProcessing]::ProcessCategory($CatName, 'Group Policy'))) {
                            $NestedObjectArray.Add([HardeningModule.IndividualResult]$Result)
                        }

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.AllowSwitchToAsyncInspection
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'AllowSwitchToAsyncInspection'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'AllowSwitchToAsyncInspection'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.oobeEnableRtpAndSigUpdate
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'oobeEnableRtpAndSigUpdate'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'oobeEnableRtpAndSigUpdate'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.IntelTDTEnabled
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'IntelTDTEnabled'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'IntelTDTEnabled'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = $((Get-ProcessMitigation -System).aslr.ForceRelocateImages)
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Mandatory ASLR'
                                Compliant    = $IndividualItemResult -eq 'on' ? $True : $false
                                Value        = $IndividualItemResult
                                Name         = 'Mandatory ASLR'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        # Verify the NX bit as shown in bcdedit /enum or Get-BcdEntry, info about numbers and values correlation: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bcd/bcdosloader-nxpolicy
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Boot Configuration Data (BCD) No-eXecute (NX) Value'
                                Compliant    = (((Get-BcdEntry).elements | Where-Object -FilterScript { $_.Name -eq 'nx' }).value -eq '3')
                                Value        = (((Get-BcdEntry).elements | Where-Object -FilterScript { $_.Name -eq 'nx' }).value -eq '3')
                                Name         = 'Boot Configuration Data (BCD) No-eXecute (NX) Value'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Smart App Control State'
                                Compliant    = ([HardeningModule.GlobalVars]::MDAVConfigCurrent.SmartAppControlState -eq 'On') ? $True : $False
                                Value        = [HardeningModule.GlobalVars]::MDAVConfigCurrent.SmartAppControlState
                                Name         = 'Smart App Control State'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.TaskSchedulerHelper]::Get('MSFT Driver Block list update', '\MSFT Driver Block list update\', 'Boolean')
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Fast weekly Microsoft recommended driver block list update'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'Fast weekly Microsoft recommended driver block list update'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        [System.Collections.Hashtable]$DefenderPlatformUpdatesChannels = @{
                            0 = 'NotConfigured'
                            2 = 'Beta'
                            3 = 'Preview'
                            4 = 'Staged'
                            5 = 'Broad'
                            6 = 'Delayed'
                        }

                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Microsoft Defender Platform Updates Channel'
                                Compliant    = 'N/A'
                                Value        = ($DefenderPlatformUpdatesChannels[[System.Int32]([HardeningModule.GlobalVars]::MDAVPreferencesCurrent).PlatformUpdatesChannel])
                                Name         = 'Microsoft Defender Platform Updates Channel'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        [System.Collections.Hashtable]$DefenderEngineUpdatesChannels = @{
                            0 = 'NotConfigured'
                            2 = 'Beta'
                            3 = 'Preview'
                            4 = 'Staged'
                            5 = 'Broad'
                            6 = 'Delayed'
                        }

                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Microsoft Defender Engine Updates Channel'
                                Compliant    = 'N/A'
                                Value        = ($DefenderEngineUpdatesChannels[[System.Int32]([HardeningModule.GlobalVars]::MDAVPreferencesCurrent).EngineUpdatesChannel])
                                Name         = 'Microsoft Defender Engine Updates Channel'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        # This covers instances where CFA is applied through Intune policy
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Controlled Folder Access'
                                Compliant    = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.EnableControlledFolderAccess -eq 1 ? $true : $false
                                Value        = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.EnableControlledFolderAccess
                                Name         = 'Controlled Folder Access'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Controlled Folder Access Exclusions'
                                Compliant    = 'N/A'
                                Value        = ([HardeningModule.GlobalVars]::MDAVPreferencesCurrent.ControlledFolderAccessAllowedApplications -join ',') # Join the array elements into a string to display them properly in the output CSV file
                                Name         = 'Controlled Folder Access Exclusions'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.DisableRestorePoint
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Enable Restore Point scanning'
                                Compliant    = ($IndividualItemResult -eq $False)
                                Value        = ($IndividualItemResult -eq $False)
                                Name         = 'Enable Restore Point scanning'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.PerformanceModeStatus
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'PerformanceModeStatus'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '0')
                                Value        = $IndividualItemResult
                                Name         = 'PerformanceModeStatus'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.EnableConvertWarnToBlock
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'EnableConvertWarnToBlock'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'EnableConvertWarnToBlock'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.BruteForceProtectionAggressiveness
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'BruteForceProtectionAggressiveness'
                                Compliant    = [System.Boolean]($IndividualItemResult -in ('1', '2'))
                                Value        = $IndividualItemResult
                                Name         = 'BruteForceProtectionAggressiveness'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.BruteForceProtectionConfiguredState
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'BruteForceProtectionConfiguredState'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '1')
                                Value        = $IndividualItemResult
                                Name         = 'BruteForceProtectionConfiguredState'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.BruteForceProtectionMaxBlockTime
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'BruteForceProtectionMaxBlockTime'
                                Compliant    = [System.Boolean]($IndividualItemResult -in ('0', '4294967295'))
                                Value        = $IndividualItemResult
                                Name         = 'BruteForceProtectionMaxBlockTime'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.RemoteEncryptionProtectionAggressiveness
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'RemoteEncryptionProtectionAggressiveness'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '2')
                                Value        = $IndividualItemResult
                                Name         = 'RemoteEncryptionProtectionAggressiveness'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.RemoteEncryptionProtectionConfiguredState
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'RemoteEncryptionProtectionConfiguredState'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '1')
                                Value        = $IndividualItemResult
                                Name         = 'RemoteEncryptionProtectionConfiguredState'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.RemoteEncryptionProtectionMaxBlockTime
                        $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'RemoteEncryptionProtectionMaxBlockTime'
                                Compliant    = [System.Boolean]($IndividualItemResult -in ('0', '4294967295'))
                                Value        = $IndividualItemResult
                                Name         = 'RemoteEncryptionProtectionMaxBlockTime'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        #Region Microsoft-Defender-Exploit-Guard-Category

                        # Get the current system's exploit mitigation policy XML file using the Get-ProcessMitigation cmdlet
                        [System.String]$RandomGUID = (New-Guid).Guid.ToString()
                        Get-ProcessMitigation -RegistryConfigFilePath ".\CurrentlyAppliedMitigations-$RandomGUID.xml"

                        # Load the XML file as an XML object
                        [System.Xml.XmlDocument]$SystemMitigationsXML = Get-Content -Path ".\CurrentlyAppliedMitigations-$RandomGUID.xml" -Force

                        # Delete the XML file after loading it
                        Remove-Item -Path ".\CurrentlyAppliedMitigations-$RandomGUID.xml" -Force

                        #Region System-Mitigations-Processing
                        # A hashtable to store the output of the current system's exploit mitigation policy XML file exported by the Get-ProcessMitigation cmdlet
                        [System.Collections.Hashtable]$ProcessMitigationsOnTheSystem = @{}

                        # Loop through each AppConfig element in the XML object
                        foreach ($App in $SystemMitigationsXML.MitigationPolicy.AppConfig) {
                            # Get the executable name of the app
                            [System.String]$Name = $App.Executable

                            # Create an empty array to store the mitigations
                            $Mitigations = New-Object -TypeName 'System.Collections.Generic.HashSet[System.String]'

                            # Loop through each child element of the app element
                            foreach ($Child in $App.ChildNodes ) {
                                # Get the name of the mitigation
                                [System.String]$Mitigation = $Child.Name

                                # Loop through each attribute of the child element
                                foreach ($Attribute in $Child.Attributes) {
                                    # Get the name and value of the attribute
                                    [System.String]$AttributeName = $Attribute.Name
                                    [System.String]$AttributeValue = $Attribute.Value

                                    # If the attribute value is true, add it to the array
                                    # We don't include the mitigations that are disabled/set to false
                                    # For example, some poorly designed git apps are incompatible with mandatory ASLR
                                    # And they pollute the output of the Get-ProcessMitigation cmdlet with items such as "<ASLR ForceRelocateImages="false" RequireInfo="false" />"
                                    if ($AttributeValue -eq 'true') {
                                        # If the attribute name is Enable, use the mitigation name instead, because we only need the names of the mitigations that are enabled for comparison with the CSV file.
                                        # Some attributes such as "<StrictHandle Enable="true" />" don't have a name so we add the mitigation's name to the array instead, which is "StrictHandle" in this case.
                                        if ($AttributeName -eq 'Enable') {
                                            [System.Void]$Mitigations.Add($Mitigation)
                                        }
                                        else {
                                            [System.Void]$Mitigations.Add($AttributeName)
                                        }
                                    }
                                }
                            }

                            # Make sure the array isn't empty which filters out apps with no mitigations or mitigations that are all disabled/set to false
                            if ($Mitigations.Count -ne 0) {
                                # Create a hashtable entry with the name and mitigations properties
                                $ProcessMitigationsOnTheSystem[$Name] = $Mitigations
                            }
                        }

                        # Create a new empty hashtable which replaces "ControlFlowGuard" with "CFG" since the shortened name is used in the CSV file and required by the the Set-ProcessMitigation cmdlet
                        [System.Collections.Hashtable]$RevisedProcessMitigationsOnTheSystem = @{}

                        # Loop over the keys and values of the original hashtable
                        foreach ($Key in $ProcessMitigationsOnTheSystem.Keys) {
                            # Get the value array for the current key
                            [System.String[]]$Value = $ProcessMitigationsOnTheSystem[$Key]
                            # Replace "ControlFlowGuard" with "CFG" in the value array
                            [System.String[]]$Value = $Value -replace 'ControlFlowGuard', 'CFG'
                            # Add the modified key-value pair to the new hashtable
                            [System.Void]$RevisedProcessMitigationsOnTheSystem.add($Key, $Value)
                        }
                        #Endregion System-Mitigations-Processing

                        #Region Harden-Windows-Security-Module-CSV-Processing
                        # Import the CSV file as an object
                        [HardeningModule.ProcessMitigationsParser+ProcessMitigationsRecords[]]$ProcessMitigations = [HardeningModule.GlobalVars]::ProcessMitigations

                        # Only keep the enabled mitigations in the CSV, then Group the data by ProgramName
                        [Microsoft.PowerShell.Commands.GroupInfo[]]$GroupedMitigations = $ProcessMitigations.Where({ $_.Action -eq 'Enable' }) | Group-Object -Property ProgramName

                        # A hashtable to store the output of the CSV file
                        [System.Collections.Hashtable]$TargetMitigations = @{}

                        # Loop through each group in the grouped mitigations array and add the ProgramName and Mitigations to the hashtable
                        foreach ($Item in $GroupedMitigations) {
                            $TargetMitigations[$Item.Name] = $Item.Group.Mitigation
                        }
                        #Endregion Harden-Windows-Security-Module-CSV-Processing

                        #Region Comparison
                        # Compare the values of the two hashtables if the keys match
                        foreach ($TargetMitigationItem in $TargetMitigations.GetEnumerator()) {

                            # Get the current key and value from hashtable containing the CSV data
                            [System.String]$ProcessName_Target = $TargetMitigationItem.Key
                            [System.String[]]$ProcessMitigations_Target = $TargetMitigationItem.Value

                            # Check if the hashtable containing the currently applied mitigations contains the same key
                            # Meaning the same executable is present in both hashtables
                            if ($RevisedProcessMitigationsOnTheSystem.ContainsKey($ProcessName_Target)) {

                                # Get the value from the applied mitigations hashtable
                                [System.String[]]$ProcessMitigations_Applied = $RevisedProcessMitigationsOnTheSystem[$ProcessName_Target]

                                # Compare the values of the two hashtables to see if they are the same without the order of the elements (process mitigations) in the arrays being considered
                                # Compare-Object produces output only if the objects are different
                                if (Compare-Object -ReferenceObject $ProcessMitigations_Target -DifferenceObject $ProcessMitigations_Applied) {

                                    # If the values are different, it means the process has different mitigations applied to it than the ones in the CSV file
                                    Write-Verbose -Message "Mitigations for $ProcessName_Target were found but are not compliant"

                                    # Increment the total number of the verifiable compliant values for each process that has a mitigation applied to it in the CSV file
                                    ([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)++

                                    $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                            FriendlyName = "Process Mitigations for: $ProcessName_Target"
                                            Compliant    = $False
                                            Value        = ($ProcessMitigations_Applied -join ',') # Join the array elements into a string to display them properly in the output CSV file
                                            Name         = "Process Mitigations for: $ProcessName_Target"
                                            Category     = $CatName
                                            Method       = 'Cmdlet'
                                        })
                                }
                                else {
                                    # If the values are the same, it means the process has the same mitigations applied to it as the ones in the CSV file
                                    Write-Verbose -Message "Mitigations for $ProcessName_Target are compliant"

                                    # Increment the total number of the verifiable compliant values for each process that has a mitigation applied to it in the CSV file
                                    ([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)++

                                    $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                            FriendlyName = "Process Mitigations for: $ProcessName_Target"
                                            Compliant    = $true
                                            Value        = ($ProcessMitigations_Target -join ',') # Join the array elements into a string to display them properly in the output CSV file
                                            Name         = "Process Mitigations for: $ProcessName_Target"
                                            Category     = $CatName
                                            Method       = 'Cmdlet'
                                        })
                                }
                            }
                            else {
                                # If the process name is not found in the hashtable containing the currently applied mitigations, it means the process doesn't have any mitigations applied to it
                                Write-Verbose -Message "Mitigations for $ProcessName_Target were not found"

                                # Increment the total number of the verifiable compliant values for each process that has a mitigation applied to it in the CSV file
                                ([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)++

                                $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                        FriendlyName = "Process Mitigations for: $ProcessName_Target"
                                        Compliant    = $False
                                        Value        = 'N/A'
                                        Name         = "Process Mitigations for: $ProcessName_Target"
                                        Category     = $CatName
                                        Method       = 'Cmdlet'
                                    })
                            }
                        }
                        #Endregion Comparison

                        #Endregion Microsoft-Defender-Exploit-Guard-Category

                        [System.Void] ([HardeningModule.GlobalVars]::FinalMegaObject).TryAdd($CatName, $NestedObjectArray)

                    }
                    catch {
                        Write-Verbose -Message $_ -Verbose
                        Throw $_
                    }
                    finally {
                        [HardeningModule.ControlledFolderAccessHandler]::reset()
                    }

                } -Name 'Invoke-MicrosoftDefender' -StreamingHost $Host
            }
            Function Invoke-AttackSurfaceReductionRules {
                [System.Management.Automation.Job2]$script:AttackSurfaceReductionRulesJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyAttackSurfaceReductionRules()
                } -Name 'Invoke-AttackSurfaceReductionRules'
            }
            Function Invoke-BitLockerSettings {
                [System.Management.Automation.Job2]$script:BitLockerSettingsJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyBitLockerSettings()
                } -Name 'Invoke-BitLockerSettings'
            }
            Function Invoke-TLSSecurity {
                [System.Management.Automation.Job2]$script:TLSSecurityJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'                  
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyTLSSecurity()
                } -Name 'Invoke-TLSSecurity'
            }
            Function Invoke-LockScreen {
                [System.Management.Automation.Job2]$script:LockScreenJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyLockScreen()
                } -Name 'Invoke-LockScreen'
            }
            Function Invoke-UserAccountControl {
                [System.Management.Automation.Job2]$script:UserAccountControlJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyUserAccountControl()
                } -Name 'Invoke-UserAccountControl'
            }
            Function Invoke-DeviceGuard {
                [System.Management.Automation.Job2]$script:DeviceGuardJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyDeviceGuard()
                } -Name 'Invoke-DeviceGuard'
            }
            Function Invoke-WindowsFirewall {
                [System.Management.Automation.Job2]$script:WindowsFirewallJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'WindowsFirewall'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                    foreach ($Result in ([HardeningModule.CategoryProcessing]::ProcessCategory($CatName, 'Group Policy'))) {
                        $NestedObjectArray.Add($Result)
                    }

                    # Verify the 3 built-in Firewall rules (for all 3 profiles) for Multicast DNS (mDNS) UDP-in are disabled
                    $IndividualItemResult = [System.Boolean]((Get-NetFirewallRule | Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') }).Enabled -inotcontains 'True')

                    $NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'mDNS UDP-In Firewall Rules are disabled'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'mDNS UDP-In Firewall Rules are disabled'
                            Category     = $CatName
                            Method       = 'Cmdlet'
                        })

                    [System.Void] ([HardeningModule.GlobalVars]::FinalMegaObject).TryAdd($CatName, $NestedObjectArray)
                } -Name 'Invoke-WindowsFirewall' -StreamingHost $Host
            }
            Function Invoke-OptionalWindowsFeatures {
                [System.Management.Automation.Job2]$script:OptionalWindowsFeaturesJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyOptionalWindowsFeatures()
                } -Name 'Invoke-OptionalWindowsFeatures'
            }
            Function Invoke-WindowsNetworking {
                [System.Management.Automation.Job2]$script:WindowsNetworkingJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyWindowsNetworking()
                } -Name 'Invoke-WindowsNetworking'
            }
            Function Invoke-MiscellaneousConfigurations {
                [System.Management.Automation.Job2]$script:MiscellaneousConfigurationsJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyMiscellaneousConfigurations()
                } -Name 'Invoke-MiscellaneousConfigurations'
            }
            Function Invoke-WindowsUpdateConfigurations {
                [System.Management.Automation.Job2]$script:WindowsUpdateConfigurationsJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyWindowsUpdateConfigurations()
                } -Name 'Invoke-WindowsUpdateConfigurations'
            }
            Function Invoke-EdgeBrowserConfigurations {
                [System.Management.Automation.Job2]$script:EdgeBrowserConfigurationsJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyEdgeBrowserConfigurations()
                } -Name 'Invoke-EdgeBrowserConfigurations'
            }
            Function Invoke-NonAdminCommands {
                [System.Management.Automation.Job2]$script:NonAdminCommandsJob = Start-ThreadJob -ThrottleLimit 14 -ScriptBlock {
                    $ErrorActionPreference = 'Stop'
                    [HardeningModule.ConfirmSystemComplianceMethods]::VerifyNonAdminCommands()
                } -Name 'Invoke-NonAdminCommands'
            }
            #Endregion Main-Functions

            Switch ($Categories) {
                'MicrosoftDefender' { Invoke-MicrosoftDefender }
                'AttackSurfaceReductionRules' { Invoke-AttackSurfaceReductionRules }
                'BitLockerSettings' { Invoke-BitLockerSettings }
                'TLSSecurity' { Invoke-TLSSecurity }
                'LockScreen' { Invoke-LockScreen }
                'UserAccountControl' { Invoke-UserAccountControl }
                'DeviceGuard' { Invoke-DeviceGuard }
                'WindowsFirewall' { Invoke-WindowsFirewall }
                'OptionalWindowsFeatures' { Invoke-OptionalWindowsFeatures }
                'WindowsNetworking' { Invoke-WindowsNetworking }
                'MiscellaneousConfigurations' { Invoke-MiscellaneousConfigurations }
                'WindowsUpdateConfigurations' { Invoke-WindowsUpdateConfigurations }
                'EdgeBrowserConfigurations' { Invoke-EdgeBrowserConfigurations }
                'NonAdminCommands' { Invoke-NonAdminCommands }
                Default {
                    # Get the values of the ValidateSet attribute of the Categories parameter of the main function
                    foreach ($Item in [HardeningModule.ComplianceCategoriex]::new().GetValidValues()) {
                        # Run all of the categories' functions if the user didn't specify any
                        . "Invoke-$Item"
                    }
                }
            }

            #Region Threading management
            $JobsToWaitFor = New-Object -TypeName System.Collections.Generic.List[System.Management.Automation.Job2]

            # If user didn't specify any categories, add all of them to the list of jobs to wait for
            if ($null -eq $Categories) {
                $JobsToWaitFor = foreach ($Cat in [HardeningModule.ComplianceCategoriex]::new().GetValidValues()) {
                    [System.String]$VariableName = $Cat + 'Job'
                    (Get-Item -Path "variable:$VariableName").Value
                }
            }
            # If user specified categories, add only the specified ones to the list of the jobs to wait for
            else {
                $JobsToWaitFor = foreach ($Cat in $Categories) {
                    [System.String]$VariableName = $Cat + 'Job'
                    (Get-Item -Path "variable:$VariableName").Value
                }
            }

            $null = Wait-Job -Job $JobsToWaitFor
            Receive-Job -Job $JobsToWaitFor
            Remove-Job -Job $JobsToWaitFor -Force
            #Endregion Threading management

            # Making sure all the true/false values have the same case
            foreach ($Item in ([HardeningModule.GlobalVars]::FinalMegaObject).Values) {
                foreach ($Item2 in $Item) {
                    try {
                        if ($Item2.Compliant -ieq 'True') {
                            $Item2.Compliant = $true
                        }
                        elseif ($Item2.Compliant -ieq 'False') {
                            $Item2.Compliant = $false
                        }
                    }
                    catch {}
                }
            }

            if ($ExportToCSV) {
                # Create an empty list to store the results based on the category order by sorting the concurrent hashtable
                $AllOrderedResults = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]

                $AllOrderedResults = foreach ($Key in [HardeningModule.ComplianceCategoriex]::new().GetValidValues()) {
                    if (([HardeningModule.GlobalVars]::FinalMegaObject).ContainsKey($Key)) {
                        foreach ($Item in ([HardeningModule.GlobalVars]::FinalMegaObject)[$Key].GetEnumerator()) {
                            $Item
                        }
                    }
                }

                # Store the results in the current working directory in a CSV files
                $AllOrderedResults | ConvertTo-Csv | Out-File -FilePath ".\Compliance Check Output $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss").CSV" -Force
            }
            function Set-CategoryFormat {
                [CmdletBinding()]
                param (
                    [ValidateSet([Colorsx])]
                    [Parameter(Mandatory)][System.String]$ColorInput,
                    [Parameter(Mandatory)][System.String]$CategoryName,
                    [Parameter(Mandatory)][System.String]$DisplayName,
                    [Parameter(Mandatory)][System.Collections.Hashtable]$ColorMap,
                    [AllowNull()]
                    [Parameter(Mandatory)][System.String[]]$Categories,
                    [ValidateSet('List', 'Table')]
                    [Parameter(Mandatory)][System.String]$Type
                )
                # If user selected specific categories and the current function call's category name is not included in them, return from this function
                if (($null -ne $Categories) -and ($CategoryName -notin $Categories)) { Return }

                # Assign the array of color codes to a variable for easier/shorter assignments
                [System.Int32[]]$RGBs = $ColorMap[$ColorInput]['Code']

                &$ColorMap[$ColorInput]['ScriptBlock'] "`n-------------$DisplayName Category-------------"

                Switch ($Type) {
                    'List' {
                        # Setting the List Format Accent the same color as the category's title
                        $PSStyle.Formatting.FormatAccent = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2]))
                        ([HardeningModule.GlobalVars]::FinalMegaObject).$CategoryName | Format-List -Property FriendlyName, @{
                            Label      = 'Compliant'
                            Expression =
                            { switch ($_.Compliant) {
                                    { $_ -eq $true } { $SwitchColor = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2])); break }
                                    { $_ -eq $false } { $SwitchColor = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break }
                                    { $_ -eq 'N/A' } { $SwitchColor = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break }
                                }
                                "$SwitchColor$($_.Compliant)$($PSStyle.Reset)"
                            }
                        }, Value, Name, Category, Method
                    }
                    'Table' {
                        # Setting the Table header the same color as the category's title
                        $PSStyle.Formatting.TableHeader = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2]))
                        ([HardeningModule.GlobalVars]::FinalMegaObject).$CategoryName | Format-Table -Property FriendlyName,
                        @{
                            Label      = 'Compliant'
                            Expression =
                            { switch ($_.Compliant) {
                                    { $_ -eq $true } { $SwitchColor = $($PSStyle.Foreground.FromRGB($RGBs[0], $RGBs[1], $RGBs[2])); break }
                                    { $_ -eq $false } { $SwitchColor = "$($PSStyle.Foreground.FromRGB(229,43,80))$($PSStyle.Blink)"; break }
                                    { $_ -eq 'N/A' } { $SwitchColor = "$($PSStyle.Foreground.FromRGB(238,255,204))"; break }
                                }
                                "$SwitchColor$($_.Compliant)$($PSStyle.Reset)"
                            }

                        }, Value -AutoSize
                    }
                }
            }

            if ($ShowAsObjectsOnly) {
                # return the main object that contains multiple nested objects
                return ([HardeningModule.GlobalVars]::FinalMegaObject)
            }
            else {
                Set-CategoryFormat -ColorInput Plum -CategoryName 'MicrosoftDefender' -DisplayName 'Microsoft Defender' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Orchid -CategoryName 'AttackSurfaceReductionRules' -DisplayName 'Attack Surface Reduction Rules' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Fuchsia -CategoryName 'BitLockerSettings' -DisplayName 'Bitlocker Category' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MediumOrchid -CategoryName 'TLSSecurity' -DisplayName 'TLS' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MediumPurple -CategoryName 'LockScreen' -DisplayName 'Lock Screen' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput BlueViolet -CategoryName 'UserAccountControl' -DisplayName 'User Account Control' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput AndroidGreen -CategoryName 'DeviceGuard' -DisplayName 'Device Guard' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Pink -CategoryName 'WindowsFirewall' -DisplayName 'Windows Firewall' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput SkyBlue -CategoryName 'OptionalWindowsFeatures' -DisplayName 'Optional Windows Features' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput HotPink -CategoryName 'WindowsNetworking' -DisplayName 'Windows Networking' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput DeepPink -CategoryName 'MiscellaneousConfigurations' -DisplayName 'Miscellaneous' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MintGreen -CategoryName 'WindowsUpdateConfigurations' -DisplayName 'Windows Update' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Orange -CategoryName 'EdgeBrowserConfigurations' -DisplayName 'Microsoft Edge' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Daffodil -CategoryName 'NonAdminCommands' -DisplayName 'Non-Admin' -ColorMap $global:ColorsMap -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')

                # Counting the number of $True Compliant values in the Final Output Object
                [System.UInt32]$TotalTrueCompliantValuesInOutPut = 0
                foreach ($Category in [HardeningModule.ComplianceCategoriex]::new().GetValidValues()) {
                    $TotalTrueCompliantValuesInOutPut += (([HardeningModule.GlobalVars]::FinalMegaObject).$Category).Where({ $_.Compliant -eq $True }).Count
                }

                # Only display the overall score if the user has not specified any categories
                if (!$Categories) {
                    switch ($True) {
                    ($TotalTrueCompliantValuesInOutPut -in 1..40) { & $WriteRainbow "$(Get-Content -Raw -Path "$([HardeningModule.GlobalVars]::Path)\Resources\Media\Text Arts\1To40.txt")`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)!" }
                    ($TotalTrueCompliantValuesInOutPut -in 41..80) { & $WriteRainbow "$(Get-Content -Raw -Path "$([HardeningModule.GlobalVars]::Path)\Resources\Media\Text Arts\41To80.txt")`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)!" }
                    ($TotalTrueCompliantValuesInOutPut -in 81..120) { & $WriteRainbow "$(Get-Content -Raw -Path "$([HardeningModule.GlobalVars]::Path)\Resources\Media\Text Arts\81To120.txt")`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)!" }
                    ($TotalTrueCompliantValuesInOutPut -in 121..160) { & $WriteRainbow "$(Get-Content -Raw -Path "$([HardeningModule.GlobalVars]::Path)\Resources\Media\Text Arts\121To160.txt")`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)!" }
                    ($TotalTrueCompliantValuesInOutPut -in 161..200) { & $WriteRainbow "$(Get-Content -Raw -Path "$([HardeningModule.GlobalVars]::Path)\Resources\Media\Text Arts\161To200.txt")`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)!" }
                    ($TotalTrueCompliantValuesInOutPut -gt 200) { & $WriteRainbow "$(Get-Content -Raw -Path "$([HardeningModule.GlobalVars]::Path)\Resources\Media\Text Arts\Above200.txt")`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $([HardeningModule.GlobalVars]::TotalNumberOfTrueCompliantValues)!" }
                    }
                }
            }
        }
        Catch {
            # Throw any unhandled errors in a terminating fashion
            Throw $_
        }
        finally {
            # End the progress bar and mark it as completed
            Write-Progress -Id 0 -Activity 'Completed' -Completed
            [HardeningModule.Miscellaneous]::CleanUp()
        }
    }
    <#
.SYNOPSIS
    Checks the compliance of a system with the Harden Windows Security script guidelines
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module
.DESCRIPTION
    Checks the compliance of a system with the Harden Windows Security script. Checks the applied Group policies, registry keys and PowerShell cmdlets used by the hardening script.
.COMPONENT
    Gpresult, Secedit, PowerShell, Registry
.FUNCTIONALITY
    Uses Gpresult and Secedit to first export the effective Group policies and Security policies, then goes through them and checks them against the Harden Windows Security's guidelines.
.EXAMPLE
    $Result = Confirm-SystemCompliance -ShowAsObjectsOnly
    ($Result['MicrosoftDefender'] | Where-Object -FilterScript { $_.Name -eq 'Controlled Folder Access Exclusions'}).Value

    Do this to get the Controlled Folder Access Programs list when using ShowAsObjectsOnly optional parameter to output an object
.EXAMPLE
    $Result = Confirm-SystemCompliance -ShowAsObjectsOnly
    $Result['MicrosoftDefender']

    Do this to only see the result for the Microsoft Defender category when using ShowAsObjectsOnly optional parameter to output an object
.EXAMPLE
    Confirm-SystemCompliance -Categories MicrosoftDefender, MiscellaneousConfigurations

    Do this to only check the compliance for the Microsoft Defender and Miscellaneous Configurations categories
.PARAMETER ExportToCSV
    Export the output to a CSV file in the current working directory
.PARAMETER ShowAsObjectsOnly
    Returns a nested object instead of writing strings on the PowerShell console, it can be assigned to a variable
.PARAMETER DetailedDisplay
    Shows the output on the PowerShell console with more details and in the list format instead of table format
.PARAMETER Categories
    Specify the categories to check compliance for. If not specified, all categories will be checked
.PARAMETER Offline
    Skips the online update check
.INPUTS
    System.Management.Automation.SwitchParameter
    System.String[]
.OUTPUTS
    System.String
    System.Collections.Concurrent.ConcurrentDictionary[System.String, HardeningModule.IndividualResult[]]
#>
}
