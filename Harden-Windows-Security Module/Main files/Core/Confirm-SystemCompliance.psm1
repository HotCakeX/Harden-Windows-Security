function Confirm-SystemCompliance {
    [CmdletBinding()]
    [OutputType([System.String], [System.Collections.Concurrent.ConcurrentDictionary[System.String, PSCustomObject[]]])]
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

                [Categoriex]::new().GetValidValues() | ForEach-Object -Process {
                    # Check if the item is already selected
                    if ($_ -notin $Existing) {
                        # Return the item
                        $_
                    }
                }
            })]
        [ValidateScript({
                if ($_ -notin [Categoriex]::new().GetValidValues()) { throw "Invalid Category Name: $_" }
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
        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$HardeningModulePath\Shared\Update-self.psm1" -Force -Verbose:$false
        Import-Module -FullyQualifiedName "$HardeningModulePath\Shared\Test-IsAdmin.psm1" -Force -Verbose:$false

        # Makes sure this cmdlet is invoked with Admin privileges
        if (-NOT (Test-IsAdmin)) {
            Throw [System.Security.AccessControl.PrivilegeNotHeldException] 'Administrator'
        }

        if (-NOT $Offline) {
            Write-Verbose -Message 'Checking for updates...'
            Update-Self -InvocationStatement $MyInvocation.Statement
        }

        Class Categoriex : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Categoriex = @(
                    'MicrosoftDefender', # 55 - 3x(N/A) = 46
                    'AttackSurfaceReductionRules', # 19
                    'BitLockerSettings', # 22 + Number of Non-OS drives which are dynamically increased
                    'TLSSecurity', # 21
                    'LockScreen', # 14
                    'UserAccountControl', # 4
                    'DeviceGuard', # 8
                    'WindowsFirewall', # 20
                    'OptionalWindowsFeatures', # 13
                    'WindowsNetworking', # 9
                    'MiscellaneousConfigurations', # 17
                    'WindowsUpdateConfigurations', # 14
                    'EdgeBrowserConfigurations', # 14
                    'NonAdminCommands' # 11
                )
                return [System.String[]]$Categoriex
            }
        }

        # Import the IndividualResult class if it's not already loaded, will become available to the thread-jobs as well since they share the same app domain
        if (-NOT ('HardeningModule.IndividualResult' -as [System.Type]) ) {
            Add-Type -Path "$HardeningModulePath\Shared\IndividualResultClass.cs"
        }

        if ((Get-CimInstance -ClassName Win32_OperatingSystem -Verbose:$false).OperatingSystemSKU -in '101', '100') {
            Write-Warning -Message 'The Windows Home edition has been detected, many features are unavailable in this edition.'
        }

        #Region Defining-Variables

        if (-NOT ('HardeningModule.GlobalVars' -as [System.Type]) ) {
            Add-Type -TypeDefinition @"
namespace HardeningModule
{
    public static class GlobalVars
    {
        public static int TotalNumberOfTrueCompliantValues = 238;
        // Making the HardeningModulePath variable available app-domain wide in a pseudo-lexical scoping manner so it can be accessed from thread jobs without having to pass it as a parameter to each job
        public static string path = $("`"$($HardeningModulePath -replace '\\', '\\')`"");

        public static object MDAVConfigCurrent;
        public static object MDAVPreferencesCurrent;
    }
}
"@ -Language CSharp
        }

        # a synced hashtable so that System.Threading.Interlocked can safely increment/decrement this value from multiple threads
        $SyncHash = [System.Collections.Hashtable]::Synchronized(@{})
        # Total number of Compliant values not equal to N/A
        $SyncHash['TotalNumberOfTrueCompliantValues'] = 238

        # Get the current configurations and preferences of the Microsoft Defender and set them as variables
        [HardeningModule.GlobalVars]::MDAVPreferencesCurrent = Get-MpPreference
        [HardeningModule.GlobalVars]::MDAVConfigCurrent = Get-MpComputerStatus

        # Import the CSV file
        [System.Object[]]$CSVResource = Import-Csv -Path "$HardeningModulePath\Resources\Registry resources.csv"

        # An object to store the FINAL results
        $FinalMegaObject = [System.Collections.Concurrent.ConcurrentDictionary[System.String, PSCustomObject[]]]::new()

        # The total number of the steps for the parent/main progress bar to render
        [System.UInt16]$TotalMainSteps = 2
        [System.UInt16]$CurrentMainStep = 0
        #EndRegion Defining-Variables

        #Region Defining-Functions-ScriptBlocks
        function ConvertFrom-IniFile {
            <#
            .SYNOPSIS
                A helper function to parse the ini file from the output of the "Secedit /export /cfg .\security_policy.inf"
            .PARAMETER IniFile
                The path to the ini file
            .INPUTS
                System.String
            .OUTPUTS
                PSCustomObject
            #>
            [CmdletBinding()]
            Param ([System.String]$IniFile)

            # Don't prompt to continue if '-Debug' is specified.
            $DebugPreference = 'Continue'

            [System.Collections.Hashtable]$IniObject = @{}
            [System.String]$SectionName = ''

            switch -regex -file $IniFile {
                '^\[(.+)\]$' {
                    # Header of the section
                    $SectionName = $matches[1]
                    #Write-Debug "Section: $SectionName"
                    $IniObject[$SectionName] = @{}
                    continue
                }
                '^(.+?)\s*=\s*(.*)$' {
                    # Name/value pair
                    [System.String]$KeyName, [System.String]$KeyValue = $matches[1..2]
                    #Write-Debug "Name: $KeyName"
                    # Write-Debug "Value: $KeyValue"
                    $IniObject[$SectionName][$KeyName] = $KeyValue
                    continue
                }
                default {
                    # Ignore blank lines or comments
                    continue
                }
            }
            return [PSCustomObject]$IniObject
        }

        $ScriptBlockInvokeCategoryProcessing = [System.Management.Automation.ScriptBlock]::Create({
                <#
            .SYNOPSIS
                A helper function for processing each item in $AllRegistryItems for each category
            .PARAMETER CatName
                Name of the hardening category to verify
            .PARAMETER Method
                The method used to verify the hardening category, which can be 'Group Policy' or 'Registry Keys'
            .INPUTS
                System.String
            .OUTPUTS
                System.Object[]
            #>
                param(
                    [System.String]$CatName,
                    [System.String]$Method
                )

                # an array to hold the output
                $Output = New-Object -TypeName System.Collections.Generic.List[PSCustomObject]

                foreach ($Item in $CSVResource | Where-Object -FilterScript { ($_.Category -eq $CatName) -and ($_.Origin -eq $Method) }) {

                    # Initialize a flag to indicate if the key exists
                    [System.Boolean]$KeyExists = $false

                    # Initialize a flag to indicate if the value exists and matches the type
                    [System.Boolean]$ValueMatches = $false

                    # Try to get the registry key
                    try {
                        $null = Get-Item -Path "Registry::$($Item.Key)"
                        # If no error is thrown, the key exists
                        $KeyExists = $true

                        # Try to get the registry value and type
                        try {
                            $RegValue = Get-ItemPropertyValue -Path "Registry::$($Item.Key)" -Name $Item.Name
                            # If no error is thrown, the value exists

                            # Check if the value matches the expected one
                            if ($RegValue -eq $Item.value) {
                                # If it matches, set the flag to true
                                $ValueMatches = $true
                            }
                        }
                        catch {
                            # If an error is thrown, the value does not exist or is not accessible
                            # Do nothing, the flag remains false
                        }
                    }
                    catch {
                        # If an error is thrown, the key does not exist or is not accessible
                        # Do nothing, the flag remains false
                    }

                    # Create a custom object with the results for this row
                    [System.Void]$Output.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = $Item.FriendlyName
                            Compliant    = $ValueMatches
                            Value        = $Item.Value
                            Name         = $Item.Name
                            Category     = $CatName
                            Method       = $Method
                        })
                }
                return $Output
            })
        #EndRegion Defining-Functions-ScriptBlocks

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
    }

    process {

        try {
            #Region Rainbow Progress Bar

            # Define a variable to store the current color index
            [System.UInt16]$Global:ColorIndex = 0

            # Create a timer object that fires every 2 seconds
            [System.Timers.Timer]$RainbowTimer = New-Object System.Timers.Timer
            $RainbowTimer.Interval = 2000 # milliseconds
            $RainbowTimer.AutoReset = $true # repeat until stopped

            # Register an event handler that changes Write-Progress' style every time the timer elapses
            [System.Management.Automation.PSEventJob]$EventHandler = Register-ObjectEvent -InputObject $RainbowTimer -EventName Elapsed -Action {

                $Global:ColorIndex++
                if ($Global:ColorIndex -ge $Global:Colors.Length) {
                    $Global:ColorIndex = 0
                }

                # Get the current color from the array
                [System.Drawing.Color]$CurrentColor = $Global:Colors[$Global:ColorIndex]
                # Set the progress bar style to use the current color and the blink effect
                $PSStyle.Progress.Style = "$($PSStyle.Foreground.FromRGB($CurrentColor.R, $CurrentColor.G, $CurrentColor.B))$($PSStyle.Blink)"
            }

            # Start the timer
            $RainbowTimer.Start()

            #Endregion Rainbow Progress Bar

            $CurrentMainStep++
            Write-Progress -Id 0 -Activity 'Gathering Security Policy Information' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

            # Get the security group policies
            $null = &"$env:SystemDrive\Windows\System32\Secedit.exe" /export /cfg .\security_policy.inf

            # Storing the output of the ini file parsing function
            [PSCustomObject]$SecurityPoliciesIni = ConvertFrom-IniFile -IniFile .\security_policy.inf

            $CurrentMainStep++
            Write-Progress -Id 0 -Activity 'Verifying the security settings' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

            #Region Main-Functions
            Function Invoke-MicrosoftDefender {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:MicrosoftDefenderJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    Try {

                        $ErrorActionPreference = 'Stop'
                        $VerbosePreference = $ParentVerbosePreference

                        # A try-Catch-finally block to revert the changes being made to the Controlled Folder Access exclusions list
                        # Which is currently required for BCD NX value verification in the MicrosoftDefender category

                        # backup the currently allowed apps list in Controlled folder access in order to restore them at the end
                        # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
                        # no user customization will be affected
                        [System.String[]]$CFAAllowedAppsBackup = (Get-MpPreference).ControlledFolderAccessAllowedApplications

                        # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
                        # so that the script can run without interruption. This change is reverted at the end.
                        foreach ($FilePath in (Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) {
                            Add-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
                        }

                        # Give the Defender internals time to process the updated exclusions list
                        Start-Sleep -Seconds '5'

                        # An array to store the nested custom objects, inside the main output object
                        $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                        [System.String]$CatName = 'MicrosoftDefender'

                        # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                        foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                            [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]$Result)
                        }

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.AllowSwitchToAsyncInspection
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'AllowSwitchToAsyncInspection'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'AllowSwitchToAsyncInspection'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.oobeEnableRtpAndSigUpdate
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'oobeEnableRtpAndSigUpdate'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'oobeEnableRtpAndSigUpdate'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.IntelTDTEnabled
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'IntelTDTEnabled'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'IntelTDTEnabled'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = $((Get-ProcessMitigation -System).aslr.ForceRelocateImages)
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Mandatory ASLR'
                                Compliant    = $IndividualItemResult -eq 'on' ? $True : $false
                                Value        = $IndividualItemResult
                                Name         = 'Mandatory ASLR'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        # Verify the NX bit as shown in bcdedit /enum or Get-BcdEntry, info about numbers and values correlation: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bcd/bcdosloader-nxpolicy
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Boot Configuration Data (BCD) No-eXecute (NX) Value'
                                Compliant    = (((Get-BcdEntry).elements | Where-Object -FilterScript { $_.Name -eq 'nx' }).value -eq '3')
                                Value        = (((Get-BcdEntry).elements | Where-Object -FilterScript { $_.Name -eq 'nx' }).value -eq '3')
                                Name         = 'Boot Configuration Data (BCD) No-eXecute (NX) Value'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Smart App Control State'
                                Compliant    = ([HardeningModule.GlobalVars]::MDAVConfigCurrent.SmartAppControlState -eq 'On') ? $True : $False
                                Value        = [HardeningModule.GlobalVars]::MDAVConfigCurrent.SmartAppControlState
                                Name         = 'Smart App Control State'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        try {
                            $IndividualItemResult = $((Get-ScheduledTask -TaskPath '\MSFT Driver Block list update\' -TaskName 'MSFT Driver Block list update' -ErrorAction SilentlyContinue) ? $True : $false)
                        }
                        catch {
                            # suppress any possible terminating errors
                        }
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
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

                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
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

                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Microsoft Defender Engine Updates Channel'
                                Compliant    = 'N/A'
                                Value        = ($DefenderEngineUpdatesChannels[[System.Int32]([HardeningModule.GlobalVars]::MDAVPreferencesCurrent).EngineUpdatesChannel])
                                Name         = 'Microsoft Defender Engine Updates Channel'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        # This covers instances where CFA is applied through Intune policy
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Controlled Folder Access'
                                Compliant    = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.EnableControlledFolderAccess -eq 1 ? $true : $false
                                Value        = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.EnableControlledFolderAccess
                                Name         = 'Controlled Folder Access'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Controlled Folder Access Exclusions'
                                Compliant    = 'N/A'
                                Value        = ([HardeningModule.GlobalVars]::MDAVPreferencesCurrent.ControlledFolderAccessAllowedApplications -join ',') # Join the array elements into a string to display them properly in the output CSV file
                                Name         = 'Controlled Folder Access Exclusions'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.DisableRestorePoint
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Enable Restore Point scanning'
                                Compliant    = ($IndividualItemResult -eq $False)
                                Value        = ($IndividualItemResult -eq $False)
                                Name         = 'Enable Restore Point scanning'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.PerformanceModeStatus
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'PerformanceModeStatus'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '0')
                                Value        = $IndividualItemResult
                                Name         = 'PerformanceModeStatus'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.EnableConvertWarnToBlock
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'EnableConvertWarnToBlock'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'EnableConvertWarnToBlock'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.BruteForceProtectionAggressiveness
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'BruteForceProtectionAggressiveness'
                                Compliant    = [System.Boolean]($IndividualItemResult -in ('1', '2'))
                                Value        = $IndividualItemResult
                                Name         = 'BruteForceProtectionAggressiveness'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.BruteForceProtectionConfiguredState
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'BruteForceProtectionConfiguredState'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '1')
                                Value        = $IndividualItemResult
                                Name         = 'BruteForceProtectionConfiguredState'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.BruteForceProtectionMaxBlockTime
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'BruteForceProtectionMaxBlockTime'
                                Compliant    = [System.Boolean]($IndividualItemResult -in ('0', '4294967295'))
                                Value        = $IndividualItemResult
                                Name         = 'BruteForceProtectionMaxBlockTime'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.RemoteEncryptionProtectionAggressiveness
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'RemoteEncryptionProtectionAggressiveness'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '2')
                                Value        = $IndividualItemResult
                                Name         = 'RemoteEncryptionProtectionAggressiveness'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.RemoteEncryptionProtectionConfiguredState
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'RemoteEncryptionProtectionConfiguredState'
                                Compliant    = [System.Boolean]($IndividualItemResult -eq '1')
                                Value        = $IndividualItemResult
                                Name         = 'RemoteEncryptionProtectionConfiguredState'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })

                        $IndividualItemResult = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.RemoteEncryptionProtectionMaxBlockTime
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
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
                        [System.Object[]]$ProcessMitigations = Import-Csv -Path "$([HardeningModule.GlobalVars]::Path)\Resources\ProcessMitigations.csv" -Delimiter ','

                        # Only keep the enabled mitigations in the CSV, then Group the data by ProgramName
                        [System.Object[]]$GroupedMitigations = $ProcessMitigations | Where-Object -FilterScript { $_.Action -eq 'Enable' } | Group-Object -Property ProgramName

                        # A hashtable to store the output of the CSV file
                        [System.Collections.Hashtable]$TargetMitigations = @{}

                        # Loop through each group in the grouped mitigations array and add the ProgramName and Mitigations to the hashtable
                        foreach ($Item in $GroupedMitigations) {
                            $TargetMitigations[$Item.Name] = $Item.Group.Mitigation
                        }
                        #Endregion Harden-Windows-Security-Module-CSV-Processing

                        #Region Comparison
                        # Compare the values of the two hashtables if the keys match
                        $TargetMitigations.GetEnumerator() | ForEach-Object -Process {

                            # Get the current key and value from hashtable containing the CSV data
                            [System.String]$ProcessName_Target = $_.Key
                            [System.String[]]$ProcessMitigations_Target = $_.Value

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
                                    $SyncHash['TotalNumberOfTrueCompliantValues']++

                                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
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
                                    $SyncHash['TotalNumberOfTrueCompliantValues']++

                                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
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
                                $SyncHash['TotalNumberOfTrueCompliantValues']++

                                [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
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

                        # Add the array of the custom objects to the main output HashTable
                        [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                    }
                    catch {
                        Write-Verbose -Message $_ -Verbose
                        Throw $_
                    }
                    finally {
                        # Reverting the PowerShell executables allow listings in Controlled folder access
                        foreach ($FilePath in (Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) {
                            Remove-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
                        }

                        # restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
                        # they will be restored as well, so user customization will remain intact
                        if ($null -ne $CFAAllowedAppsBackup) {
                            Set-MpPreference -ControlledFolderAccessAllowedApplications $CFAAllowedAppsBackup
                        }
                    }

                } -Name 'Invoke-MicrosoftDefender' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-AttackSurfaceReductionRules {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:AttackSurfaceReductionRulesJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'AttackSurfaceReductionRules'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Individual ASR rules verification
                    [System.String[]]$Ids = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.AttackSurfaceReductionRules_Ids
                    [System.String[]]$Actions = [HardeningModule.GlobalVars]::MDAVPreferencesCurrent.AttackSurfaceReductionRules_Actions

                    # If $Ids variable is not empty, convert them to lower case because some IDs can be in upper case and result in inaccurate comparison
                    if ($Ids) { $Ids = $Ids.tolower() }

                    # Hashtable to store the descriptions for each ID
                    [System.Collections.Hashtable]$ASRsTable = @{
                        '26190899-1602-49e8-8b27-eb1d0a1ce869' = 'Block Office communication application from creating child processes'
                        'd1e49aac-8f56-4280-b9ba-993a6d77406c' = 'Block process creations originating from PSExec and WMI commands'
                        'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4' = 'Block untrusted and unsigned processes that run from USB'
                        '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' = 'Block Win32 API calls from Office macros'
                        '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c' = 'Block Adobe Reader from creating child processes'
                        '3b576869-a4ec-4529-8536-b80a7769e899' = 'Block Office applications from creating executable content'
                        'd4f940ab-401b-4efc-aadc-ad5f3c50688a' = 'Block all Office applications from creating child processes'
                        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)'
                        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550' = 'Block executable content from email client and webmail'
                        '01443614-cd74-433a-b99e-2ecdc07bfc25' = 'Block executable files from running unless they meet a prevalence; age or trusted list criterion'
                        '5beb7efe-fd9a-4556-801d-275e5ffc04cc' = 'Block execution of potentially obfuscated scripts'
                        'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'Block persistence through WMI event subscription'
                        '75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84' = 'Block Office applications from injecting code into other processes'
                        '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'Block abuse of exploited vulnerable signed drivers'
                        'c1db55ab-c21a-4637-bb3f-a12568109d35' = 'Use advanced protection against ransomware'
                        'd3e037e1-3eb8-44c8-a917-57927947596d' = 'Block JavaScript or VBScript from launching downloaded executable content'
                        '33ddedf1-c6e0-47cb-833e-de6133960387' = 'Block rebooting machine in Safe Mode'
                        'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb' = 'Block use of copied or impersonated system tools'
                    }

                    # Loop over each ID in the hashtable
                    foreach ($Name in $ASRsTable.Keys) {

                        # Check if the $Ids array is not empty and current ID is present in the $Ids array
                        if ($Ids -and $Ids -icontains $Name) {
                            # If yes, check if the $Actions array is not empty
                            if ($Actions) {
                                # If yes, use the index of the ID in the array to access the action value
                                $Action = $Actions[$Ids.IndexOf($Name)]
                            }
                            else {
                                # If no, assign a default action value of 0
                                $Action = 0
                            }
                        }
                        else {
                            # If no, assign a default action value of 0
                            $Action = 0
                        }

                        # An exception for the ASR rule with ID 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb'
                        # 'Block use of copied or impersonated system tools'
                        # Because it's in preview and is set to 6 for Warn instead of 1 for block
                        if ($Name -eq 'c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb') {
                            # Create a custom object with properties
                            [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                    FriendlyName = $ASRsTable[$name]
                                    Compliant    = [System.Boolean]($Action -in '6', '1') # Either 6 or 1 is compliant and acceptable
                                    Value        = $Action
                                    Name         = $Name
                                    Category     = $CatName
                                    Method       = 'Cmdlet'
                                })

                        }
                        else {
                            # Create a custom object with properties
                            [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                    FriendlyName = $ASRsTable[$name]
                                    Compliant    = [System.Boolean]($Action -eq 1) # Compare action value with 1 and cast to boolean
                                    Value        = $Action
                                    Name         = $Name
                                    Category     = $CatName
                                    Method       = 'Cmdlet'
                                })
                        }
                    }

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-AttackSurfaceReductionRules' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-BitLockerSettings {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:BitLockerSettingsJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'
                    $PSDefaultParameterValues = @{
                        'Get-BitLockerVolume:Verbose' = $false
                        'Get-Volume:Verbose'          = $false
                    }

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'BitLockerSettings'

                    # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
                    # The Script will show this by emitting True \ False for On \ Off respectively.
                    # if the type is not already loaded, load it
                    if (-NOT ('SystemInfo.NativeMethods' -as [System.Type])) {
                        Write-Verbose -Message 'Loading SystemInfo.NativeMethods type' -Verbose:$($ParentVerbosePreference -eq 'Continue')
                        Add-Type -Path "$([HardeningModule.GlobalVars]::Path)\Shared\SystemInfoNativeMethods.cs" -Verbose:$($ParentVerbosePreference -eq 'Continue')
                    }
                    else {
                        Write-Verbose -Message 'SystemInfo.NativeMethods type is already loaded, skipping loading it again.' -Verbose:$($ParentVerbosePreference -eq 'Continue')
                    }

                    # Returns true or false depending on whether Kernel DMA Protection is on or off
                    [System.Boolean]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

                    # Get the status of Bitlocker DMA protection
                    try {
                        [System.Int32]$BitlockerDMAProtectionStatus = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE' -Name 'DisableExternalDMAUnderLock' -ErrorAction SilentlyContinue
                    }
                    catch {
                        # -ErrorAction SilentlyContinue wouldn't suppress the error if the path exists but property doesn't, so using try-catch
                    }
                    # Bitlocker DMA counter measure status
                    # Returns true if only either Kernel DMA protection is on and Bitlocker DMA protection if off
                    # or Kernel DMA protection is off and Bitlocker DMA protection is on
                    [System.Boolean]$ItemState = ($BootDMAProtection -xor ($BitlockerDMAProtectionStatus -eq '1')) ? $True : $False

                    # Create a custom object with 5 properties to store them as nested objects inside the main output object
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'DMA protection'
                            Compliant    = $ItemState
                            Value        = $ItemState
                            Name         = 'DMA protection'
                            Category     = $CatName
                            Method       = 'Group Policy'
                        })

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # To detect if Hibernate is enabled and set to full
                    if (-NOT ([HardeningModule.GlobalVars]::MDAVConfigCurrent.IsVirtualMachine)) {
                        try {
                            $IndividualItemResult = $($((Get-ItemProperty 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -ErrorAction SilentlyContinue).HiberFileType) -eq 2 ? $True : $False)
                        }
                        catch {
                            # suppress the errors if any
                        }
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Hibernate is set to full'
                                Compliant    = [System.Boolean]($IndividualItemResult)
                                Value        = [System.Boolean]($IndividualItemResult)
                                Name         = 'Hibernate is set to full'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })
                    }
                    else {
                        $SyncHash['TotalNumberOfTrueCompliantValues']--
                    }

                    # OS Drive encryption verifications
                    # Check if BitLocker is on for the OS Drive
                    # The ProtectionStatus remains off while the drive is encrypting or decrypting
                    if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'on') {

                        # Get the key protectors of the OS Drive
                        [System.String[]]$KeyProtectors = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector.keyprotectortype

                        # Check if TPM+PIN and recovery password are being used - Normal Security level
                        if (($KeyProtectors -contains 'Tpmpin') -and ($KeyProtectors -contains 'RecoveryPassword')) {

                            [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                    FriendlyName = 'Secure OS Drive encryption'
                                    Compliant    = $True
                                    Value        = 'Normal Security Level'
                                    Name         = 'Secure OS Drive encryption'
                                    Category     = $CatName
                                    Method       = 'Cmdlet'

                                })
                        }

                        # Check if TPM+PIN+StartupKey and recovery password are being used - Enhanced security level
                        elseif (($KeyProtectors -contains 'TpmPinStartupKey') -and ($KeyProtectors -contains 'RecoveryPassword')) {

                            [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                    FriendlyName = 'Secure OS Drive encryption'
                                    Compliant    = $True
                                    Value        = 'Enhanced Security Level'
                                    Name         = 'Secure OS Drive encryption'
                                    Category     = $CatName
                                    Method       = 'Cmdlet'
                                })
                        }

                        else {
                            [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                    FriendlyName = 'Secure OS Drive encryption'
                                    Compliant    = $false
                                    Value        = $false
                                    Name         = 'Secure OS Drive encryption'
                                    Category     = $CatName
                                    Method       = 'Cmdlet'
                                })
                        }
                    }
                    else {
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Secure OS Drive encryption'
                                Compliant    = $false
                                Value        = $false
                                Name         = 'Secure OS Drive encryption'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })
                    }
                    #region Non-OS-Drive-BitLocker-Drives-Encryption-Verification
                    # Get the list of non OS volumes
                    [System.Object[]]$NonOSBitLockerVolumes = Get-BitLockerVolume | Where-Object -FilterScript { $_.volumeType -ne 'OperatingSystem' }

                    # Get all the volumes and filter out removable ones
                    [System.Object[]]$RemovableVolumes = Get-Volume | Where-Object -FilterScript { ($_.DriveType -eq 'Removable') -and $_.DriveLetter }

                    # Check if there is any removable volumes
                    if ($RemovableVolumes) {

                        # Get the letters of all the removable volumes
                        [System.String[]]$RemovableVolumesLetters = foreach ($RemovableVolume in $RemovableVolumes) {
                            $(($RemovableVolume).DriveLetter + ':' )
                        }

                        # Filter out removable drives from BitLocker volumes to process
                        $NonOSBitLockerVolumes = $NonOSBitLockerVolumes | Where-Object -FilterScript { $_.MountPoint -notin $RemovableVolumesLetters }
                    }

                    # Check if there is any non-OS volumes
                    if ($NonOSBitLockerVolumes) {

                        # Loop through each non-OS volume and verify their encryption
                        foreach ($MountPoint in $($NonOSBitLockerVolumes | Sort-Object).MountPoint) {

                            # Increase the number of available compliant values for each non-OS drive that was found
                            $SyncHash['TotalNumberOfTrueCompliantValues']++

                            # If status is unknown, that means the non-OS volume is encrypted and locked, if it's on then it's on
                            if ((Get-BitLockerVolume -MountPoint $MountPoint).ProtectionStatus -in 'on', 'Unknown') {

                                # Check 1: if Recovery Password and Auto Unlock key protectors are available on the drive
                                [System.Object[]]$KeyProtectors = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector.keyprotectortype
                                if (($KeyProtectors -contains 'RecoveryPassword') -or ($KeyProtectors -contains 'Password')) {

                                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                            FriendlyName = "Secure Drive $MountPoint encryption"
                                            Compliant    = $True
                                            Value        = 'Encrypted'
                                            Name         = "Secure Drive $MountPoint encryption"
                                            Category     = $CatName
                                            Method       = 'Cmdlet'
                                        })
                                }
                                else {
                                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                            FriendlyName = "Secure Drive $MountPoint encryption"
                                            Compliant    = $false
                                            Value        = 'Not properly encrypted'
                                            Name         = "Secure Drive $MountPoint encryption"
                                            Category     = $CatName
                                            Method       = 'Cmdlet'
                                        })
                                }
                            }
                            else {
                                [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                        FriendlyName = "Secure Drive $MountPoint encryption"
                                        Compliant    = $false
                                        Value        = 'Not encrypted'
                                        Name         = "Secure Drive $MountPoint encryption"
                                        Category     = $CatName
                                        Method       = 'Cmdlet'
                                    })
                            }
                        }
                    }
                    #endregion Non-OS-Drive-BitLocker-Drives-Encryption-Verification

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)
                } -Name 'Invoke-BitLockerSettings' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-TLSSecurity {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:TLSSecurityJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'TLSSecurity'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # ECC Curves
                    [System.Object[]]$ECCCurves = Get-TlsEccCurve
                    [System.Object[]]$List = ('nistP521', 'curve25519', 'NistP384', 'NistP256')
                    # Make sure both arrays are completely identical in terms of members and their exact position
                    # If this variable is empty that means both arrays are completely identical
                    $IndividualItemResult = Compare-Object -ReferenceObject $ECCCurves -DifferenceObject $List -SyncWindow 0

                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'ECC Curves and their positions'
                            Compliant    = [System.Boolean]($IndividualItemResult ? $false : $True)
                            Value        = ($List -join ',') # Join the array elements into a string to display them properly in the output CSV file
                            Name         = 'ECC Curves and their positions'
                            Category     = $CatName
                            Method       = 'Cmdlet'
                        })

                    # Process items in Registry resources.csv file with "Registry Keys" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Registry Keys')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-TLSSecurity' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-LockScreen {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:LockScreenJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'LockScreen'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\InactivityTimeoutSecs'] -eq '4,120') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Machine inactivity limit'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Machine inactivity limit'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableCAD'] -eq '4,0') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Interactive logon: Do not require CTRL+ALT+DEL'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Interactive logon: Do not require CTRL+ALT+DEL'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\MaxDevicePasswordFailedAttempts'] -eq '4,5') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Interactive logon: Machine account lockout threshold'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Interactive logon: Machine account lockout threshold'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLockedUserId'] -eq '4,4') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Interactive logon: Display user information when the session is locked'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Interactive logon: Display user information when the session is locked'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayUserName'] -eq '4,1') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = "Interactive logon: Don't display username at sign-in"
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = "Interactive logon: Don't display username at sign-in"
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'System Access'['LockoutBadCount'] -eq '5') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Account lockout threshold'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Account lockout threshold'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'System Access'['LockoutDuration'] -eq '1440') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Account lockout duration'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Account lockout duration'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'System Access'['ResetLockoutCount'] -eq '1440') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Reset account lockout counter after'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Reset account lockout counter after'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\DontDisplayLastUserName'] -eq '4,1') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = "Interactive logon: Don't display last signed-in"
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = "Interactive logon: Don't display last signed-in"
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)
                } -Name 'Invoke-LockScreen' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-UserAccountControl {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:UserAccountControlJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'UserAccountControl'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin'] -eq '4,2') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'UAC: Behavior of the elevation prompt for administrators in Admin Approval Mode'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'UAC: Behavior of the elevation prompt for administrators in Admin Approval Mode'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorUser'] -eq '4,0') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'UAC: Automatically deny elevation requests on Standard accounts'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'UAC: Automatically deny elevation requests on Standard accounts'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]($($SecurityPoliciesIni.'Registry Values'['MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ValidateAdminCodeSignatures'] -eq '4,1') ? $True : $False)
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'UAC: Only elevate executables that are signed and validated'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'UAC: Only elevate executables that are signed and validated'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)
                } -Name 'Invoke-UserAccountControl' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-DeviceGuard {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:DeviceGuardJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'DeviceGuard'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-DeviceGuard' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-WindowsFirewall {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:WindowsFirewallJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'WindowsFirewall'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Verify the 3 built-in Firewall rules (for all 3 profiles) for Multicast DNS (mDNS) UDP-in are disabled
                    $IndividualItemResult = [System.Boolean](
                (Get-NetFirewallRule |
                        Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') }).Enabled -inotcontains 'True'
                    )

                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'mDNS UDP-In Firewall Rules are disabled'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'mDNS UDP-In Firewall Rules are disabled'
                            Category     = $CatName
                            Method       = 'Cmdlet'
                        })

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-WindowsFirewall' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-OptionalWindowsFeatures {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:OptionalWindowsFeaturesJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'OptionalWindowsFeatures'

                    # Windows PowerShell handling Windows optional features verifications
                    [System.String[]]$Results = @()
                    $Results = powershell.exe {
                        [System.Boolean]$PowerShell1 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2).State -eq 'Disabled'
                        [System.Boolean]$PowerShell2 = (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State -eq 'Disabled'
                        [System.String]$WorkFoldersClient = (Get-WindowsOptionalFeature -Online -FeatureName WorkFolders-Client).state
                        [System.String]$InternetPrintingClient = (Get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-Features).state
                        [System.String]$WindowsMediaPlayer = (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*Media.WindowsMediaPlayer*' }).state
                        [System.String]$MDAG = (Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard).state
                        [System.String]$WindowsSandbox = (Get-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM).state
                        [System.String]$HyperV = (Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V).state
                        [System.String]$WMIC = (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*wmic*' }).state
                        [System.String]$IEMode = (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*Browser.InternetExplorer*' }).state
                        [System.String]$LegacyNotepad = (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*Microsoft.Windows.Notepad.System*' }).state
                        [System.String]$LegacyWordPad = (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*Microsoft.Windows.WordPad*' }).state
                        [System.String]$PowerShellISE = (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*Microsoft.Windows.PowerShell.ISE*' }).state
                        [System.String]$StepsRecorder = (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*App.StepsRecorder*' }).state
                        # returning the output of the script block as an array
                        Return $PowerShell1, $PowerShell2, $WorkFoldersClient, $InternetPrintingClient, $WindowsMediaPlayer, $MDAG, $WindowsSandbox, $HyperV, $WMIC, $IEMode, $LegacyNotepad, $LegacyWordPad, $PowerShellISE, $StepsRecorder
                    }
                    # Verify PowerShell v2 is disabled
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'PowerShell v2 is disabled'
                            Compliant    = ($Results[0] -and $Results[1]) ? $True : $False
                            Value        = ($Results[0] -and $Results[1]) ? $True : $False
                            Name         = 'PowerShell v2 is disabled'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Work folders is disabled
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Work Folders client is disabled'
                            Compliant    = [System.Boolean]($Results[2] -eq 'Disabled')
                            Value        = [System.String]$Results[2]
                            Name         = 'Work Folders client is disabled'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Internet Printing Client is disabled
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Internet Printing Client is disabled'
                            Compliant    = [System.Boolean]($Results[3] -eq 'Disabled')
                            Value        = [System.String]$Results[3]
                            Name         = 'Internet Printing Client is disabled'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify the old Windows Media Player is disabled
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Windows Media Player (legacy) is disabled'
                            Compliant    = [System.Boolean]($Results[4] -eq 'NotPresent')
                            Value        = [System.String]$Results[4]
                            Name         = 'Windows Media Player (legacy) is disabled'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify MDAG is disabled
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Microsoft Defender Application Guard is enabled'
                            Compliant    = [System.Boolean]($Results[5] -eq 'Disabled')
                            Value        = [System.String]$Results[5]
                            Name         = 'Microsoft Defender Application Guard is enabled'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Windows Sandbox is enabled
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Windows Sandbox is enabled'
                            Compliant    = [System.Boolean]($Results[6] -eq 'Enabled')
                            Value        = [System.String]$Results[6]
                            Name         = 'Windows Sandbox is enabled'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Hyper-V is enabled
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Hyper-V is enabled'
                            Compliant    = [System.Boolean]($Results[7] -eq 'Enabled')
                            Value        = [System.String]$Results[7]
                            Name         = 'Hyper-V is enabled'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify WMIC is not present
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'WMIC is not present'
                            Compliant    = [System.Boolean]($Results[8] -eq 'NotPresent')
                            Value        = [System.String]$Results[8]
                            Name         = 'WMIC is not present'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Internet Explorer mode functionality for Edge is not present
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Internet Explorer mode functionality for Edge is not present'
                            Compliant    = [System.Boolean]($Results[9] -eq 'NotPresent')
                            Value        = [System.String]$Results[9]
                            Name         = 'Internet Explorer mode functionality for Edge is not present'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Legacy Notepad is not present
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Legacy Notepad is not present'
                            Compliant    = [System.Boolean]($Results[10] -eq 'NotPresent')
                            Value        = [System.String]$Results[10]
                            Name         = 'Legacy Notepad is not present'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Legacy WordPad is not present
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'WordPad is not present'
                            Compliant    = [System.Boolean]($Results[11] -eq 'NotPresent')
                            Value        = [System.String]$Results[11]
                            Name         = 'WordPad is not present'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify PowerShell ISE is not present
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'PowerShell ISE is not present'
                            Compliant    = [System.Boolean]($Results[12] -eq 'NotPresent')
                            Value        = [System.String]$Results[12]
                            Name         = 'PowerShell ISE is not present'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Verify Steps Recorder is not present
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Steps Recorder is not present'
                            Compliant    = [System.Boolean]($Results[13] -eq 'NotPresent')
                            Value        = [System.String]$Results[13]
                            Name         = 'Steps Recorder is not present'
                            Category     = $CatName
                            Method       = 'Optional Windows Features'
                        })

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-OptionalWindowsFeatures' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-WindowsNetworking {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:WindowsNetworkingJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'WindowsNetworking'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Check network location of all connections to see if they are public
                    $Condition = Get-NetConnectionProfile | ForEach-Object -Process { $_.NetworkCategory -eq 'public' }
                    [System.Boolean]$IndividualItemResult = -NOT ($Condition -contains $false) ? $True : $false

                    # Verify a Security setting using Cmdlet
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Network Location of all connections set to Public'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Network Location of all connections set to Public'
                            Category     = $CatName
                            Method       = 'Cmdlet'
                        })

                    # Verify a Security setting using registry
                    try {
                        $IndividualItemResult = [System.Boolean]((Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'EnableLMHOSTS' -ErrorAction SilentlyContinue) -eq '0')
                    }
                    catch {
                        # -ErrorAction SilentlyContinue wouldn't suppress the error if the path exists but property doesn't, so using try-catch
                    }
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Disable LMHOSTS lookup protocol on all network adapters'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Disable LMHOSTS lookup protocol on all network adapters'
                            Category     = $CatName
                            Method       = 'Registry Key'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\Machine'] -eq '7,') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Network access: Remotely accessible registry paths'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Network access: Remotely accessible registry paths'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Verify a Security Group Policy setting
                    $IndividualItemResult = [System.Boolean]$($SecurityPoliciesIni.'Registry Values'['MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\Machine'] -eq '7,') ? $True : $False
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Network access: Remotely accessible registry paths and subpaths'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Network access: Remotely accessible registry paths and subpaths'
                            Category     = $CatName
                            Method       = 'Security Group Policy'
                        })

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-WindowsNetworking' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-MiscellaneousConfigurations {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:MiscellaneousConfigurationsJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'MiscellaneousConfigurations'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Verify an Audit policy is enabled - only supports systems with English-US language
                    if ((Get-Culture).Name -eq 'en-US') {
                        $IndividualItemResult = [System.Boolean](((auditpol /get /subcategory:"Other Logon/Logoff Events" /r | ConvertFrom-Csv).'Inclusion Setting' -eq 'Success and Failure') ? $True : $False)
                        [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                                FriendlyName = 'Audit policy for Other Logon/Logoff Events'
                                Compliant    = $IndividualItemResult
                                Value        = $IndividualItemResult
                                Name         = 'Audit policy for Other Logon/Logoff Events'
                                Category     = $CatName
                                Method       = 'Cmdlet'
                            })
                    }
                    else {
                        $SyncHash['TotalNumberOfTrueCompliantValues']--
                    }

                    # Checking if all user accounts are part of the Hyper-V security Group
                    # Get all the enabled user account SIDs
                    [System.Security.Principal.SecurityIdentifier[]]$EnabledUsers = (Get-LocalUser | Where-Object -FilterScript { $_.Enabled -eq 'True' }).SID
                    # Get the members of the Hyper-V Administrators security group using their SID
                    [System.Security.Principal.SecurityIdentifier[]]$GroupMembers = (Get-LocalGroupMember -SID 'S-1-5-32-578').SID

                    # Make sure the arrays are not empty
                    if (($null -ne $EnabledUsers) -and ($null -ne $GroupMembers)) {
                        # only outputs data if there is a difference, so when it returns $false it means both arrays are equal
                        $IndividualItemResult = [System.Boolean](-NOT (Compare-Object -ReferenceObject $EnabledUsers -DifferenceObject $GroupMembers) )
                    }
                    else {
                        # if either of the arrays are null or empty then return false
                        [System.Boolean]$IndividualItemResult = $false
                    }

                    # Saving the results of the Hyper-V administrators members group to the array as an object
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'All users are part of the Hyper-V Administrators group'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'All users are part of the Hyper-V Administrators group'
                            Category     = $CatName
                            Method       = 'Cmdlet'
                        })

                    # Process items in Registry resources.csv file with "Registry Keys" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Registry Keys')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)


                } -Name 'Invoke-MiscellaneousConfigurations' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-WindowsUpdateConfigurations {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:WindowsUpdateConfigurationsJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'WindowsUpdateConfigurations'

                    # Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Group Policy')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Verify a Security setting using registry
                    try {
                        $IndividualItemResult = [System.Boolean]((Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'RestartNotificationsAllowed2' -ErrorAction SilentlyContinue) -eq '1')
                    }
                    catch {
                        # -ErrorAction SilentlyContinue wouldn't suppress the error if the path exists but property doesn't, so using try-catch
                    }
                    [System.Void]$NestedObjectArray.Add([HardeningModule.IndividualResult]@{
                            FriendlyName = 'Enable restart notification for Windows update'
                            Compliant    = $IndividualItemResult
                            Value        = $IndividualItemResult
                            Name         = 'Enable restart notification for Windows update'
                            Category     = $CatName
                            Method       = 'Registry Key'
                        })

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-WindowsUpdateConfigurations' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-EdgeBrowserConfigurations {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:EdgeBrowserConfigurationsJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'EdgeBrowserConfigurations'

                    # Process items in Registry resources.csv file with "Registry Keys" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Registry Keys')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-EdgeBrowserConfigurations' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            Function Invoke-NonAdminCommands {
                Param ($SyncHash, $FinalMegaObject, $SecurityPoliciesIni)

                [System.Management.Automation.Job2]$script:NonAdminCommandsJob = Start-ThreadJob -ScriptBlock {

                    Param ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $ParentVerbosePreference, $SecurityPoliciesIni)

                    $ErrorActionPreference = 'Stop'

                    $NestedObjectArray = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                    [System.String]$CatName = 'NonAdminCommands'

                    # Process items in Registry resources.csv file with "Registry Keys" origin and add them to the $NestedObjectArray array as custom objects
                    foreach ($Result in (&$ScriptBlockInvokeCategoryProcessing -catname $CatName -Method 'Registry Keys')) {
                        [System.Void]$NestedObjectArray.Add($Result)
                    }

                    # Add the array of the custom objects to the main output HashTable
                    [System.Void]$FinalMegaObject.TryAdd($CatName, $NestedObjectArray)

                } -Name 'Invoke-NonAdminCommands' -StreamingHost $Host -ArgumentList ($SyncHash, $FinalMegaObject, $ScriptBlockInvokeCategoryProcessing, $CSVResource, $VerbosePreference, $SecurityPoliciesIni)
            }
            #Endregion Main-Functions

            Switch ($Categories) {
                'MicrosoftDefender' { Invoke-MicrosoftDefender -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'AttackSurfaceReductionRules' { Invoke-AttackSurfaceReductionRules -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'BitLockerSettings' { Invoke-BitLockerSettings -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'TLSSecurity' { Invoke-TLSSecurity -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'LockScreen' { Invoke-LockScreen -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'UserAccountControl' { Invoke-UserAccountControl -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'DeviceGuard' { Invoke-DeviceGuard -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'WindowsFirewall' { Invoke-WindowsFirewall -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'OptionalWindowsFeatures' { Invoke-OptionalWindowsFeatures -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'WindowsNetworking' { Invoke-WindowsNetworking -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'MiscellaneousConfigurations' { Invoke-MiscellaneousConfigurations -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'WindowsUpdateConfigurations' { Invoke-WindowsUpdateConfigurations -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'EdgeBrowserConfigurations' { Invoke-EdgeBrowserConfigurations -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                'NonAdminCommands' { Invoke-NonAdminCommands -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni }
                Default {
                    # Get the values of the ValidateSet attribute of the Categories parameter of the main function
                    [Categoriex]::new().GetValidValues() | ForEach-Object -Process {
                        # Run all of the categories' functions if the user didn't specify any
                        . "Invoke-$_" -SyncHash $SyncHash -FinalMegaObject $FinalMegaObject -SecurityPoliciesIni $SecurityPoliciesIni
                    }
                }
            }

            #Region Threading management
            $JobsToWaitFor = New-Object -TypeName System.Collections.Generic.List[System.Management.Automation.Job2]

            # If user didn't specify any categories, add all of them to the list of jobs to wait for
            if ($null -eq $Categories) {
                foreach ($Cat in [Categoriex]::new().GetValidValues()) {
                    [System.Void]$JobsToWaitFor.Add((Get-Variable -Name ($Cat + 'Job') -ValueOnly))
                }
            }
            # If user specified categories, add only the specified ones to the list of the jobs to wait for
            else {
                foreach ($Cat in $Categories) {
                    [System.Void]$JobsToWaitFor.Add((Get-Variable -Name ($Cat + 'Job') -ValueOnly))
                }
            }

            $null = Wait-Job -Job $JobsToWaitFor
            Receive-Job -Job $JobsToWaitFor
            Remove-Job -Job $JobsToWaitFor -Force
            #Endregion Threading management

            if ($ExportToCSV) {
                # Create an empty list to store the results based on the category order by sorting the concurrent hashtable
                $AllOrderedResults = New-Object -TypeName System.Collections.Generic.List[HardeningModule.IndividualResult]
                foreach ($Key in [Categoriex]::new().GetValidValues()) {
                    if ($FinalMegaObject.ContainsKey($Key)) {
                        foreach ($Item in $FinalMegaObject[$Key].GetEnumerator()) {
                            [System.Void]$AllOrderedResults.Add([HardeningModule.IndividualResult]$Item)
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
                    [Parameter(Mandatory)][PSCustomObject[]]$FinalMegaObject,
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
                        $FinalMegaObject.$CategoryName | Format-List -Property FriendlyName, @{
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
                        $FinalMegaObject.$CategoryName | Format-Table -Property FriendlyName,
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

                        } , Value -AutoSize
                    }
                }
            }

            if ($ShowAsObjectsOnly) {
                # return the main object that contains multiple nested objects
                return $FinalMegaObject
            }
            else {
                Set-CategoryFormat -ColorInput Plum -CategoryName 'MicrosoftDefender' -DisplayName 'Microsoft Defender' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Orchid -CategoryName 'AttackSurfaceReductionRules' -DisplayName 'Attack Surface Reduction Rules' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Fuchsia -CategoryName 'BitLockerSettings' -DisplayName 'Bitlocker Category' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MediumOrchid -CategoryName 'TLSSecurity' -DisplayName 'TLS' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MediumPurple -CategoryName 'LockScreen' -DisplayName 'Lock Screen' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput BlueViolet -CategoryName 'UserAccountControl' -DisplayName 'User Account Control' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput AndroidGreen -CategoryName 'DeviceGuard' -DisplayName 'Device Guard' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Pink -CategoryName 'WindowsFirewall' -DisplayName 'Windows Firewall' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput SkyBlue -CategoryName 'OptionalWindowsFeatures' -DisplayName 'Optional Windows Features' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput HotPink -CategoryName 'WindowsNetworking' -DisplayName 'Windows Networking' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput DeepPink -CategoryName 'MiscellaneousConfigurations' -DisplayName 'Miscellaneous' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput MintGreen -CategoryName 'WindowsUpdateConfigurations' -DisplayName 'Windows Update' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Orange -CategoryName 'EdgeBrowserConfigurations' -DisplayName 'Microsoft Edge' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')
                Set-CategoryFormat -ColorInput Daffodil -CategoryName 'NonAdminCommands' -DisplayName 'Non-Admin' -ColorMap $global:ColorsMap -FinalMegaObject $FinalMegaObject -Categories:$Categories -Type ($DetailedDisplay ? 'List' : 'Table')

                # Counting the number of $True Compliant values in the Final Output Object
                [System.UInt32]$TotalTrueCompliantValuesInOutPut = 0
                foreach ($Category in [Categoriex]::new().GetValidValues()) {
                    $TotalTrueCompliantValuesInOutPut += ($FinalMegaObject.$Category).Where({ $_.Compliant -eq $True }).Count
                }

                #Region ASCII-Arts
                [System.String]$WhenValue1To40 = @'
                OH

                N
                　   O
                　　　 O
                　　　　 o
                　　　　　o
                　　　　　 o
                　　　　　o
                　　　　 。
                　　　 。
                　　　.
                　　　.
                　　　 .
                　　　　.

'@

                [System.String]$WhenValue41To80 = @'

‎‏‏‎‏‏‎⣿⣿⣷⡁⢆⠈⠕⢕⢂⢕⢂⢕⢂⢔⢂⢕⢄⠂⣂⠂⠆⢂⢕⢂⢕⢂⢕⢂⢕⢂
‎‏‏‎‏‏‎⣿⣿⣿⡷⠊⡢⡹⣦⡑⢂⢕⢂⢕⢂⢕⢂⠕⠔⠌⠝⠛⠶⠶⢶⣦⣄⢂⢕⢂⢕
‎‏‏‎‏‏‎⣿⣿⠏⣠⣾⣦⡐⢌⢿⣷⣦⣅⡑⠕⠡⠐⢿⠿⣛⠟⠛⠛⠛⠛⠡⢷⡈⢂⢕⢂
‎‏‏‎‏‏‎⠟⣡⣾⣿⣿⣿⣿⣦⣑⠝⢿⣿⣿⣿⣿⣿⡵⢁⣤⣶⣶⣿⢿⢿⢿⡟⢻⣤⢑⢂
‎‏‏‎‏‏‎⣾⣿⣿⡿⢟⣛⣻⣿⣿⣿⣦⣬⣙⣻⣿⣿⣷⣿⣿⢟⢝⢕⢕⢕⢕⢽⣿⣿⣷⣔
‎‏‏‎‏‏‎⣿⣿⠵⠚⠉⢀⣀⣀⣈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣗⢕⢕⢕⢕⢕⢕⣽⣿⣿⣿⣿
‎‏‏‎‏‏‎⢷⣂⣠⣴⣾⡿⡿⡻⡻⣿⣿⣴⣿⣿⣿⣿⣿⣿⣷⣵⣵⣵⣷⣿⣿⣿⣿⣿⣿⡿
‎‏‏‎‏‏‎⢌⠻⣿⡿⡫⡪⡪⡪⡪⣺⣿⣿⣿⣿⣿⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃
‎‏‏‎‏‏‎⠣⡁⠹⡪⡪⡪⡪⣪⣾⣿⣿⣿⣿⠋⠐⢉⢍⢄⢌⠻⣿⣿⣿⣿⣿⣿⣿⣿⠏⠈
‎‏‏‎‏‏‎⡣⡘⢄⠙⣾⣾⣾⣿⣿⣿⣿⣿⣿⡀⢐⢕⢕⢕⢕⢕⡘⣿⣿⣿⣿⣿⣿⠏⠠⠈
‎‏‏‎‏‏‎⠌⢊⢂⢣⠹⣿⣿⣿⣿⣿⣿⣿⣿⣧⢐⢕⢕⢕⢕⢕⢅⣿⣿⣿⣿⡿⢋⢜⠠⠈
‎‏‏‎‏‏‎⠄⠁⠕⢝⡢⠈⠻⣿⣿⣿⣿⣿⣿⣿⣷⣕⣑⣑⣑⣵⣿⣿⣿⡿⢋⢔⢕⣿⠠⠈
‎‏‏‎‏‏‎⠨⡂⡀⢑⢕⡅⠂⠄⠉⠛⠻⠿⢿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⢔⢕⢕⣿⣿⠠⠈
‎‏‏‎‏‏‎⠄⠪⣂⠁⢕⠆⠄⠂⠄⠁⡀⠂⡀⠄⢈⠉⢍⢛⢛⢛⢋⢔⢕⢕⢕⣽⣿⣿⠠⠈

'@

                [System.String]$WhenValue81To120 = @'

            ⣿⡟⠙⠛⠋⠩⠭⣉⡛⢛⠫⠭⠄⠒⠄⠄⠄⠈⠉⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿
            ⣿⡇⠄⠄⠄⠄⣠⠖⠋⣀⡤⠄⠒⠄⠄⠄⠄⠄⠄⠄⠄⠄⣈⡭⠭⠄⠄⠄⠉⠙
            ⣿⡇⠄⠄⢀⣞⣡⠴⠚⠁⠄⠄⢀⠠⠄⠄⠄⠄⠄⠄⠄⠉⠄⠄⠄⠄⠄⠄⠄⠄
            ⣿⡇⠄⡴⠁⡜⣵⢗⢀⠄⢠⡔⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄
            ⣿⡇⡜⠄⡜⠄⠄⠄⠉⣠⠋⠠⠄⢀⡄⠄⠄⣠⣆⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸
            ⣿⠸⠄⡼⠄⠄⠄⠄⢰⠁⠄⠄⠄⠈⣀⣠⣬⣭⣛⠄⠁⠄⡄⠄⠄⠄⠄⠄⢀⣿
            ⣏⠄⢀⠁⠄⠄⠄⠄⠇⢀⣠⣴⣶⣿⣿⣿⣿⣿⣿⡇⠄⠄⡇⠄⠄⠄⠄⢀⣾⣿
            ⣿⣸⠈⠄⠄⠰⠾⠴⢾⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⢁⣾⢀⠁⠄⠄⠄⢠⢸⣿⣿
            ⣿⣿⣆⠄⠆⠄⣦⣶⣦⣌⣿⣿⣿⣿⣷⣋⣀⣈⠙⠛⡛⠌⠄⠄⠄⠄⢸⢸⣿⣿
            ⣿⣿⣿⠄⠄⠄⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠇⠈⠄⠄⠄⠄⠄⠈⢸⣿⣿
            ⣿⣿⣿⠄⠄⠄⠘⣿⣿⣿⡆⢀⣈⣉⢉⣿⣿⣯⣄⡄⠄⠄⠄⠄⠄⠄⠄⠈⣿⣿
            ⣿⣿⡟⡜⠄⠄⠄⠄⠙⠿⣿⣧⣽⣍⣾⣿⠿⠛⠁⠄⠄⠄⠄⠄⠄⠄⠄⠃⢿⣿
            ⣿⡿⠰⠄⠄⠄⠄⠄⠄⠄⠄⠈⠉⠩⠔⠒⠉⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠐⠘⣿
            ⣿⠃⠃⠄⠄⠄⠄⠄⠄⣀⢀⠄⠄⡀⡀⢀⣤⣴⣤⣤⣀⣀⠄⠄⠄⠄⠄⠄⠁⢹

'@

                [System.String]$WhenValue121To160 = @'

                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⡷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡿⠋⠈⠻⣮⣳⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣴⣾⡿⠋⠀⠀⠀⠀⠙⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣤⣶⣿⡿⠟⠛⠉⠀⠀⠀⠀⠀⠀⠀⠈⠛⠛⠿⠿⣿⣷⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⡿⠟⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠛⠻⠿⣿⣶⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⣀⣠⣤⣤⣀⡀⠀⠀⣀⣴⣿⡿⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣄⡀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣄⠀⠀
                ⢀⣤⣾⡿⠟⠛⠛⢿⣿⣶⣾⣿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣿⣷⣦⣀⣀⣤⣶⣿⡿⠿⢿⣿⡀⠀
                ⣿⣿⠏⠀⢰⡆⠀⠀⠉⢿⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⢿⡿⠟⠋⠁⠀⠀⢸⣿⠇⠀
                ⣿⡟⠀⣀⠈⣀⡀⠒⠃⠀⠙⣿⡆⠀⠀⠀⠀⠀⠀⠀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠇⠀
                ⣿⡇⠀⠛⢠⡋⢙⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠀⠀
                ⣿⣧⠀⠀⠀⠓⠛⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠛⠋⠀⠀⢸⣧⣤⣤⣶⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠀⠀
                ⣿⣿⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠻⣷⣶⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⠁⠀⠀
                ⠈⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣴⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⡏⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣿⡄⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠛⠻⠿⢿⣿⣷⣶⣦⣤⣄⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡄⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⣶⣤⣤⣀⡀⠀⠀⠀⢀⣴⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡿⣄
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠿⠿⣿⣷⣶⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣹
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⢸⣧
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣆⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣶⣾⣿⣿⣿⣿⣤⣄⣀⡀⠀⠀⠀⣿
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⢿⣻⣷⣶⣾⣿⣿⡿⢯⣛⣛⡋⠁⠀⠀⠉⠙⠛⠛⠿⣿⣿⡷⣶⣿

'@

                [System.String]$WhenValue161To200 = @'

                ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠔⠶⠒⠉⠈⠸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠪⣦⢄⣀⡠⠁⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣤⣤⣤⣤⣄⣀⣀⣀⣀⣀⣀⣀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠈⠉⠀⠀⠀⣰⣶⣶⣦⠶⠛⠋⠉⠀⠀⠀⠀⠀⠀⠀⠉⠉⢷⡔⠒⠚⢽⠃⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣰⣿⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⢅⢰⣾⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⣀⡴⠞⠛⠉⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣧⠀⠀⠀⠀⠀
                ⠀⣀⣀⣤⣤⡞⠋⠀⠀⠀⢠⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⡇⠀⠀⠀⠀
                ⢸⡏⠉⣴⠏⠀⠀⠀⠀⠀⢸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀
                ⠈⣧⢰⠏⠀⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀⠀⠰⠯⠥⠠⠒⠄⠀⠀⠀⠀⠀⠀⢠⠀⣿⠀⠀⠀⠀
                ⠀⠈⣿⠀⠀⠀⠀⠀⠀⠀⠈⡧⢀⢻⠿⠀⠲⡟⣞⠀⠀⠀⠀⠈⠀⠁⠀⠀⠀⠀⠀⢀⠆⣰⠇⠀⠀⠀⠀
                ⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⣧⡀⠃⠀⠀⠀⠱⣼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣂⡴⠋⠀⣀⡀⠀⠀
                ⠀⠀⢹⡄⠀⠀⠀⠀⠀⠀⠀⠹⣜⢄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠒⠒⠿⡻⢦⣄⣰⠏⣿⠀⠀
                ⠀⠀⠀⢿⡢⡀⠀⠀⠀⠀⠀⠀⠙⠳⢮⣥⣤⣤⠶⠖⠒⠛⠓⠀⠀⠀⠀⠀⠀⠀⠀⠀⠑⢌⢻⣴⠏⠀⠀
                ⠀⠀⠀⠀⠻⣮⣒⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⣤⣀⣀⣀⣤⡴⠖⠛⢻⡆⠀⠀⠀⠀⠀⠀⢣⢻⡄⠀⠀
                ⠀⠀⠀⠀⠀⠀⠉⠛⠒⠶⠶⡶⢶⠛⠛⠁⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⠞⠁⠀⠀⠀⠀⠀⠀⠈⢜⢧⣄⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⠃⠇⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠉⢻⠀⠀⠀⠀⠀⠀⠀⢀⣀⠀⠀⠉⠈⣷
                ⠀⠀⠀⠀⠀⠀⠀⣼⠟⠷⣿⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⠲⠶⢶⣶⠶⠶⢛⣻⠏⠙⠛⠛⠛⠁
                ⠀⠀⠀⠀⠀⠀⠀⠈⠷⣤⣀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠉⠛⠓⠚⠋⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣟⡂⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢹⡟⡟⢻⡟⠛⢻⡄⠀⠀⣸⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠈⠷⠧⠾⠀⠀⠀⠻⣦⡴⠏⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

'@

                [System.String]$WhenValueAbove200 = @'
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⢠⣶⣶⣶⣦⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⠟⠛⢿⣶⡄⠀⢀⣀⣤⣤⣦⣤⡀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⢠⣿⠋⠀⠀⠈⠙⠻⢿⣶⣶⣶⣶⣶⣶⣶⣿⠟⠀⠀⠀⠀⠹⣿⡿⠟⠋⠉⠁⠈⢻⣷⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⣼⡧⠀⠀⠀⠀⠀⠀⠀⠉⠁⠀⠀⠀⠀⣾⡏⠀⠀⢠⣾⢶⣶⣽⣷⣄⡀⠀⠀⠀⠈⣿⡆⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⢸⣧⣾⠟⠉⠉⠙⢿⣿⠿⠿⠿⣿⣇⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⢸⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣷⣄⣀⣠⣼⣿⠀⠀⠀⠀⣸⣿⣦⡀⠀⠈⣿⡄⠀⠀⠀
                ⠀⠀⠀⠀⠀⢠⣾⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠉⠻⣷⣤⣤⣶⣿⣧⣿⠃⠀⣰⣿⠁⠀⠀⠀
                ⠀⠀⠀⠀⠀⣾⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠹⣿⣀⠀⠀⣀⣴⣿⣧⠀⠀⠀⠀
                ⠀⠀⠀⠀⢸⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠻⠿⠿⠛⠉⢸⣿⠀⠀⠀⠀
                ⢀⣠⣤⣤⣼⣿⣤⣄⠀⠀⠀⡶⠟⠻⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣶⣶⡄⠀⠀⠀⠀⢀⣀⣿⣄⣀⠀⠀
                ⠀⠉⠉⠉⢹⣿⣩⣿⠿⠿⣶⡄⠀⠀⠀⠀⠀⠀⠀⢀⣤⠶⣤⡀⠀⠀⠀⠀⠀⠿⡿⠃⠀⠀⠀⠘⠛⠛⣿⠋⠉⠙⠃
                ⠀⠀⠀⣤⣼⣿⣿⡇⠀⠀⠸⣿⠀⠀⠀⠀⠀⠀⠀⠘⠿⣤⡼⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣼⣿⣀⠀⠀⠀
                ⠀⠀⣾⡏⠀⠈⠙⢧⠀⠀⠀⢿⣧⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⠟⠙⠛⠓⠀
                ⠀⠀⠹⣷⡀⠀⠀⠀⠀⠀⠀⠈⠉⠙⠻⣷⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠰⣶⣿⣯⡀⠀⠀⠀⠀
                ⠀⠀⠀⠈⠻⣷⣄⠀⠀⠀⢀⣴⠿⠿⠗⠈⢻⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣾⠟⠋⠉⠛⠷⠄⠀⠀
                ⠀⠀⠀⠀⠀⢸⡏⠀⠀⠀⢿⣇⠀⢀⣠⡄⢘⣿⣶⣶⣤⣤⣤⣤⣀⣤⣤⣤⣤⣶⣶⡿⠿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠘⣿⡄⠀⠀⠈⠛⠛⠛⠋⠁⣼⡟⠈⠻⣿⣿⣿⣿⡿⠛⠛⢿⣿⣿⣿⣡⣾⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠙⢿⣦⣄⣀⣀⣀⣀⣴⣾⣿⡁⠀⠀⠀⡉⣉⠁⠀⠀⣠⣾⠟⠉⠉⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠛⠛⠛⠛⠉⠀⠹⣿⣶⣤⣤⣷⣿⣧⣴⣾⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
                ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠻⢦⣭⡽⣯⣡⡴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

'@
                #Endregion ASCII-Arts

                # Only display the overall score if the user has not specified any categories
                if (!$Categories) {
                    switch ($True) {
                    ($TotalTrueCompliantValuesInOutPut -in 1..40) { & $WriteRainbow "$WhenValue1To40`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $($SyncHash['TotalNumberOfTrueCompliantValues'])!" }
                    ($TotalTrueCompliantValuesInOutPut -in 41..80) { & $WriteRainbow "$WhenValue41To80`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $($SyncHash['TotalNumberOfTrueCompliantValues'])!" }
                    ($TotalTrueCompliantValuesInOutPut -in 81..120) { & $WriteRainbow "$WhenValue81To120`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $($SyncHash['TotalNumberOfTrueCompliantValues'])!" }
                    ($TotalTrueCompliantValuesInOutPut -in 121..160) { & $WriteRainbow "$WhenValue121To160`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $($SyncHash['TotalNumberOfTrueCompliantValues'])!" }
                    ($TotalTrueCompliantValuesInOutPut -in 161..200) { & $WriteRainbow "$WhenValue161To200`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $($SyncHash['TotalNumberOfTrueCompliantValues'])!" }
                    ($TotalTrueCompliantValuesInOutPut -gt 200) { & $WriteRainbow "$WhenValueAbove200`nYour compliance score is $TotalTrueCompliantValuesInOutPut out of $($SyncHash['TotalNumberOfTrueCompliantValues'])!" }
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

            #Region stopping rainbow progress bar

            # Stop the timer
            $RainbowTimer.Stop()

            # Unregister the event handler
            Unregister-Event -SourceIdentifier $EventHandler.Name -Force

            # Remove the event handler's job
            Remove-Job -Job $EventHandler -Force

            #Endregion stopping rainbow progress bar

            # Clean up
            Remove-Item -Path '.\security_policy.inf' -Force
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
    System.Collections.Concurrent.ConcurrentDictionary[System.String, PSCustomObject[]]
#>
}
