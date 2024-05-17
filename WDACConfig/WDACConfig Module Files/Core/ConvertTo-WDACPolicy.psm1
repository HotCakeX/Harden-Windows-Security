Function ConvertTo-WDACPolicy {
    [CmdletBinding(
        DefaultParameterSetName = 'All'
    )]
    param(
        [Alias('AddLogs')]
        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [System.IO.FileInfo]$PolicyToAddLogsTo,

        [Alias('BaseFile')]
        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.IO.FileInfo]$BasePolicyFile,

        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $fakeBoundParameters)

                [System.String[]]$PolicyGUIDs = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }).PolicyID

                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                $PolicyGUIDs | Where-Object -FilterScript { $_ -notin $Existing } | ForEach-Object -Process { "'{0}'" -f $_ }
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Alias('BaseGUID')]
        [System.Guid]$BasePolicyGUID,

        [Alias('Src')]
        [ValidateSet('MDEAdvancedHunting', 'LocalEventLogs', 'EVTXFiles')]
        [Parameter(Mandatory = $false)][System.String]$Source = 'LocalEventLogs',

        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                [System.String[]]$Policies = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.FriendlyName) -and ($_.PolicyID -eq $_.BasePolicyID) }).FriendlyName

                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                $Policies | Where-Object -FilterScript { $_ -notin $Existing } | ForEach-Object -Process { "'{0}'" -f $_ }
            })]
        [Alias('FilterNames')]
        [Parameter(Mandatory = $false)][System.String[]]$FilterByPolicyNames,

        [Alias('Duration')]
        [ValidateSet('Minutes', 'Hours', 'Days')]
        [Parameter(Mandatory = $false)][System.String]$TimeSpan
    )

    DynamicParam {

        # Create a new dynamic parameter dictionary
        $ParamDictionary = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()

        # If TimeSpanAgo parameter was used, create a mandatory parameter to ask for the value
        if ($PSBoundParameters['TimeSpan']) {

            # Create a parameter attribute collection
            $TimeSpanAgo_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

            # Create a mandatory attribute and add it to the collection
            [System.Management.Automation.ParameterAttribute]$TimeSpanAgo_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $TimeSpanAgo_MandatoryAttrib.Mandatory = $true
            $TimeSpanAgo_AttributesCollection.Add($TimeSpanAgo_MandatoryAttrib)

            # Create an alias attribute and add it to the collection
            $TimeSpanAgo_AliasAttrib = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList 'Past'
            $TimeSpanAgo_AttributesCollection.Add($TimeSpanAgo_AliasAttrib)

            # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
            [System.Management.Automation.RuntimeDefinedParameter]$TimeSpanAgo = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('TimeSpanAgo', [System.UInt64], $TimeSpanAgo_AttributesCollection)

            # Add the dynamic parameter object to the dictionary
            $ParamDictionary.Add('TimeSpanAgo', $TimeSpanAgo)
        }

        # Offer different parameters based on the source selected
        switch ($PSBoundParameters['Source']) {

            # If user selected 'MDEAdvancedHunting' as the source, then create a mandatory parameter to ask for the .CSV file(s) path(s)
            'MDEAdvancedHunting' {
                # Opens File picker GUI so that user can select .CSV files
                [System.Management.Automation.ScriptBlock]$ArgumentCompleterCSVFilePathsPicker = {
                    # Create a new OpenFileDialog object
                    [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
                    # Set the filter to show only CSV files
                    $Dialog.Filter = 'CSV files (*.CSV)|*.CSV'
                    # Set the title of the dialog
                    $Dialog.Title = 'Select Microsoft Defender for Endpoint Advanced Hunting CSV files'
                    # Allow multiple CSV files to be selected
                    $Dialog.Multiselect = $true
                    $Dialog.ShowPreview = $true
                    # Show the dialog and get the result
                    [System.String]$Result = $Dialog.ShowDialog()
                    # If the user clicked OK, return the selected file paths
                    if ($Result -eq 'OK') {
                        return "`"$($Dialog.FileNames -join '","')`""
                    }
                }

                # Create a parameter attribute collection
                $MDEAHLogs_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

                # Create an argument completer attribute and add it to the collection
                [System.Management.Automation.ArgumentCompleterAttribute]$MDEAHLogs_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterCSVFilePathsPicker)
                $MDEAHLogs_AttributesCollection.Add($MDEAHLogs_ArgumentCompleterAttrib)

                # Create a mandatory attribute and add it to the collection
                [System.Management.Automation.ParameterAttribute]$MDEAHLogs_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
                $MDEAHLogs_MandatoryAttrib.Mandatory = $true
                $MDEAHLogs_AttributesCollection.Add($MDEAHLogs_MandatoryAttrib)

                # Create an alias attribute and add it to the collection
                $MDEAHLogs_AliasAttrib = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList 'MDELogs'
                $MDEAHLogs_AttributesCollection.Add($MDEAHLogs_AliasAttrib)

                # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
                [System.Management.Automation.RuntimeDefinedParameter]$MDEAHLogs = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('MDEAHLogs', [System.IO.FileInfo[]], $MDEAHLogs_AttributesCollection)

                # Add the dynamic parameter object to the dictionary
                $ParamDictionary.Add('MDEAHLogs', $MDEAHLogs)

                break
            }

            'EVTXFiles' {

                # Opens File picker GUI so that user can select .EVTX files
                [System.Management.Automation.ScriptBlock]$ArgumentCompleterEVTXFilePathsPicker = {
                    # Create a new OpenFileDialog object
                    [System.Windows.Forms.OpenFileDialog]$Dialog = New-Object -TypeName 'System.Windows.Forms.OpenFileDialog'
                    # Set the filter to show only EVTX files
                    $Dialog.Filter = 'EVTX files (*.evtx)|*.evtx'
                    # Set the title of the dialog
                    $Dialog.Title = 'Select .evtx files to convert to WDAC policy'
                    # Allow multiple EVTX files to be selected
                    $Dialog.Multiselect = $true
                    $Dialog.ShowPreview = $true
                    # Show the dialog and get the result
                    [System.String]$Result = $Dialog.ShowDialog()
                    # If the user clicked OK, return the selected file paths
                    if ($Result -eq 'OK') {
                        return "`"$($Dialog.FileNames -join '","')`""
                    }
                }

                # Create a parameter attribute collection
                $EVTXLogs_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

                # Create an argument completer attribute and add it to the collection
                [System.Management.Automation.ArgumentCompleterAttribute]$EVTXLogs_ArgumentCompleterAttrib = New-Object -TypeName System.Management.Automation.ArgumentCompleterAttribute($ArgumentCompleterEVTXFilePathsPicker)
                $EVTXLogs_AttributesCollection.Add($EVTXLogs_ArgumentCompleterAttrib)

                # Create a mandatory attribute and add it to the collection
                [System.Management.Automation.ParameterAttribute]$EVTXLogs_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
                $EVTXLogs_MandatoryAttrib.Mandatory = $true
                $EVTXLogs_AttributesCollection.Add($EVTXLogs_MandatoryAttrib)

                # Create an alias attribute and add it to the collection
                $EVTXLogs_AliasAttrib = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList 'Evtx'
                $EVTXLogs_AttributesCollection.Add($EVTXLogs_AliasAttrib)

                # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
                [System.Management.Automation.RuntimeDefinedParameter]$EVTXLogs = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('EVTXLogs', [System.IO.FileInfo[]], $EVTXLogs_AttributesCollection)

                # Add the dynamic parameter object to the dictionary
                $ParamDictionary.Add('EVTXLogs', $EVTXLogs)

                break
            }
        }

        #Region-KernelModeOnly-Parameter

        # Create a parameter attribute collection
        $KernelModeOnly_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

        # Create a mandatory attribute and add it to the collection
        [System.Management.Automation.ParameterAttribute]$KernelModeOnly_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $KernelModeOnly_MandatoryAttrib.Mandatory = $false
        $KernelModeOnly_AttributesCollection.Add($KernelModeOnly_MandatoryAttrib)

        # Create an alias attribute and add it to the collection
        $KernelModeOnly_AliasAttrib = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList 'KMode'
        $KernelModeOnly_AttributesCollection.Add($KernelModeOnly_AliasAttrib)

        # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
        [System.Management.Automation.RuntimeDefinedParameter]$KernelModeOnly = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('KernelModeOnly', [System.Management.Automation.SwitchParameter], $KernelModeOnly_AttributesCollection)

        # Add the dynamic parameter object to the dictionary
        $ParamDictionary.Add('KernelModeOnly', $KernelModeOnly)

        #Endregion-KernelModeOnly-Parameter

        #Region-LogType-Parameter

        # Create a parameter attribute collection
        $LogType_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

        # Create a mandatory attribute and add it to the collection
        [System.Management.Automation.ParameterAttribute]$LogType_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $LogType_MandatoryAttrib.Mandatory = $false
        $LogType_AttributesCollection.Add($LogType_MandatoryAttrib)

        # Create a ValidateSet attribute with the allowed values
        [System.Management.Automation.ValidateSetAttribute]$LogType_ValidateSetAttrib = New-Object -TypeName System.Management.Automation.ValidateSetAttribute('Audit', 'Blocked')
        $LogType_AttributesCollection.Add($LogType_ValidateSetAttrib)

        # Create an alias attribute and add it to the collection
        $LogType_AliasAttrib = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList 'LogKind'
        $LogType_AttributesCollection.Add($LogType_AliasAttrib)

        # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
        [System.Management.Automation.RuntimeDefinedParameter]$LogType = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('LogType', [System.String], $LogType_AttributesCollection)

        # Add the dynamic parameter object to the dictionary
        $ParamDictionary.Add('LogType', $LogType)

        #Endregion-LogType-Parameter

        #Region-Deploy-Parameter

        # Create a parameter attribute collection
        $Deploy_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

        # Create a mandatory attribute and add it to the collection
        [System.Management.Automation.ParameterAttribute]$Deploy_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $Deploy_MandatoryAttrib.Mandatory = $false
        $Deploy_AttributesCollection.Add($Deploy_MandatoryAttrib)

        # Create an alias attribute and add it to the collection
        $Deploy_AliasAttrib = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList 'Up'
        $Deploy_AttributesCollection.Add($Deploy_AliasAttrib)

        # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
        [System.Management.Automation.RuntimeDefinedParameter]$Deploy = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('Deploy', [System.Management.Automation.SwitchParameter], $Deploy_AttributesCollection)

        # Add the dynamic parameter object to the dictionary
        $ParamDictionary.Add('Deploy', $Deploy)

        #Endregion-Deploy-Parameter

        #Region-ExtremeVisibility-Parameter

        # Create a parameter attribute collection
        $ExtremeVisibility_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

        # Create a mandatory attribute and add it to the collection
        [System.Management.Automation.ParameterAttribute]$ExtremeVisibility_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $ExtremeVisibility_MandatoryAttrib.Mandatory = $false
        $ExtremeVisibility_AttributesCollection.Add($ExtremeVisibility_MandatoryAttrib)

        $ExtremeVisibility_AliasAttrib = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList 'XVis'
        $ExtremeVisibility_AttributesCollection.Add($ExtremeVisibility_AliasAttrib)

        # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
        [System.Management.Automation.RuntimeDefinedParameter]$ExtremeVisibility = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('ExtremeVisibility', [System.Management.Automation.SwitchParameter], $ExtremeVisibility_AttributesCollection)

        # Add the dynamic parameter object to the dictionary
        $ParamDictionary.Add('ExtremeVisibility', $ExtremeVisibility)

        #Endregion-ExtremeVisibility-Parameter

        #Region-SkipVersionCheck-Parameter

        # Create a parameter attribute collection
        $SkipVersionCheck_AttributesCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]

        # Create a mandatory attribute and add it to the collection
        [System.Management.Automation.ParameterAttribute]$SkipVersionCheck_MandatoryAttrib = New-Object -TypeName System.Management.Automation.ParameterAttribute
        $SkipVersionCheck_MandatoryAttrib.Mandatory = $false
        $SkipVersionCheck_AttributesCollection.Add($SkipVersionCheck_MandatoryAttrib)

        # Create a dynamic parameter object with the attributes already assigned: Name, Type, and Attributes Collection
        [System.Management.Automation.RuntimeDefinedParameter]$SkipVersionCheck = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('SkipVersionCheck', [System.Management.Automation.SwitchParameter], $SkipVersionCheck_AttributesCollection)

        # Add the dynamic parameter object to the dictionary
        $ParamDictionary.Add('SkipVersionCheck', $SkipVersionCheck)

        #Endregion-SkipVersionCheck-Parameter

        return $ParamDictionary
    }

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'ConvertTo-WDACPolicy: Importing the required sub-modules'
        # Defining list of generic modules required for this cmdlet to import
        [System.String[]]$ModulesToImport = @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\Shared\Receive-CodeIntegrityLogs.psm1",
            "$ModuleRootPath\Shared\New-AppxPackageCiPolicy.psm1",
            "$ModuleRootPath\Shared\New-EmptyPolicy.psm1",
            "$ModuleRootPath\Shared\Get-RuleRefs.psm1",
            "$ModuleRootPath\Shared\Get-FileRules.psm1",
            "$ModuleRootPath\Shared\New-StagingArea.psm1",
            "$ModuleRootPath\Shared\Set-LogPropertiesVisibility.psm1",
            "$ModuleRootPath\Shared\Select-LogProperties.psm1"
        )
        # Add XML Ops module to the list of modules to import
        $ModulesToImport += (Get-ChildItem -File -Filter '*.psm1' -LiteralPath "$ModuleRootPath\XMLOps").FullName
        Import-Module -FullyQualifiedName $ModulesToImport -Force

        # Since Dynamic parameters are only available in the parameter dictionary, we have to access them using $PSBoundParameters or assign them manually to another variable in the function's scope
        New-Variable -Name 'TimeSpanAgo' -Value $PSBoundParameters['TimeSpanAgo'] -Force
        New-Variable -Name 'MDEAHLogs' -Value $PSBoundParameters['MDEAHLogs'] -Force
        New-Variable -Name 'EVTXLogs' -Value $PSBoundParameters['EVTXLogs'] -Force
        New-Variable -Name 'KernelModeOnly' -Value $PSBoundParameters['KernelModeOnly'] -Force
        New-Variable -Name 'LogType' -Value ($PSBoundParameters['LogType'] ?? 'Audit') -Force
        New-Variable -Name 'Deploy' -Value $PSBoundParameters['Deploy'] -Force
        New-Variable -Name 'ExtremeVisibility' -Value $PSBoundParameters['ExtremeVisibility'] -Force
        New-Variable -Name 'SkipVersionCheck' -Value $PSBoundParameters['SkipVersionCheck'] -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        # Defining a staging area for the current
        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'ConvertTo-WDACPolicy'

        # If TimeSpan parameter was selected
        if ($TimeSpan) {

            # Get the current time
            [System.DateTime]$CurrentDateTime = Get-Date

            # Create the $StartTime variable based on the user input TimeSpanAgo parameter
            switch ($TimeSpan) {
                'Minutes' { [System.DateTime]$StartTime = $CurrentDateTime.AddMinutes(-$TimeSpanAgo) -as [System.DateTime] }
                'Hours' { [System.DateTime]$StartTime = $CurrentDateTime.AddHours(-$TimeSpanAgo) -as [System.DateTime] }
                'Days' { [System.DateTime]$StartTime = $CurrentDateTime.AddDays(-$TimeSpanAgo) -as [System.DateTime] }
            }
        }

        # Save the current date in a variable as string
        [System.String]$CurrentDate = $(Get-Date -Format "MM-dd-yyyy 'at' HH-mm-ss")
    }

    Process {

        Try {

            Switch ($Source) {

                'LocalEventLogs' {

                    # To store the logs that user selects using GUI
                    [PSCustomObject[]]$SelectedLogs = @()

                    # The paths to the policy files to be merged together to produce the final Supplemental policy
                    [System.IO.FileInfo[]]$PolicyFilesToMerge = @()

                    # Initializing some flags
                    [System.Boolean]$HasKernelFiles = $false
                    [System.Boolean]$HasNormalFiles = $false

                    # The total number of the main steps for the progress bar to render
                    [System.UInt16]$TotalSteps = 5
                    [System.UInt16]$CurrentStep = 0

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity "Collecting $LogType events" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PostProcessing OnlyExisting -PolicyName:$FilterByPolicyNames -Date:$StartTime -Type:$LogType
                    [PSCustomObject[]]$EventsToDisplay = Select-LogProperties -Logs $EventsToDisplay

                    # If the KernelModeOnly switch is used, then filter the events by the 'Requested Signing Level' property
                    if ($KernelModeOnly) {
                        $EventsToDisplay = $EventsToDisplay | Where-Object -FilterScript { $_.'SI Signing Scenario' -eq 'Kernel-Mode' }
                    }

                    if (($null -eq $EventsToDisplay) -and ($EventsToDisplay.Count -eq 0)) {
                        Write-ColorfulText -Color HotPink -InputText 'No logs were found to display based on the current filters. Exiting...'
                        return
                    }

                    #Region Out-GridView properties visibility settings

                    # If the ExtremeVisibility switch is used, then display all the properties of the logs without any filtering
                    if (-NOT $ExtremeVisibility) {
                        Set-LogPropertiesVisibility -LogType Evtx/Local -EventsToDisplay $EventsToDisplay
                    }

                    #Endregion Out-GridView properties visibility settings

                    <#
                Will enable this section once this issue has been fixed: https://github.com/PowerShell/GraphicalTools/issues/235

                if ($AlternateDisplay) {

                    if (-NOT (Get-InstalledModule -Name Microsoft.PowerShell.ConsoleGuiTools -ErrorAction SilentlyContinue)) {
                        Write-Verbose -Message 'ConvertTo-WDACPolicy: Installing the Microsoft.PowerShell.ConsoleGuiTools module'
                        Install-Module -Name Microsoft.PowerShell.ConsoleGuiTools -Force
                    }

                    # Display the logs in a console grid view using outside module
                    $SelectedLogs = $EventsToDisplay | Out-ConsoleGridView -Title "$($EventsToDisplay.count) $LogType Code Integrity Logs" -OutputMode Multiple
                }
                #>

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Displaying the logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Display the logs in a grid view using the build-in cmdlet
                    $SelectedLogs = $EventsToDisplay | Out-GridView -OutputMode Multiple -Title "Displaying $($EventsToDisplay.count) $LogType Code Integrity Logs"

                    Write-Verbose -Message "ConvertTo-WDACPolicy: Selected logs count: $($SelectedLogs.count)"

                    if (!$BasePolicyGUID -and !$BasePolicyFile -and !$PolicyToAddLogsTo) {
                        Write-ColorfulText -Color HotPink -InputText 'A more specific parameter was not provided to define what to do with the selected logs. Exiting...'
                        return
                    }

                    # If the user has selected any logs, then create a WDAC policy for them, otherwise return
                    if ($null -eq $SelectedLogs) {
                        return
                    }

                    Write-Verbose -Message 'ConvertTo-WDACPolicy: Creating a temporary folder to store the symbolic links to the files and for WDAC polices'
                    [System.IO.DirectoryInfo]$SymLinksStorage = New-Item -Path (Join-Path -Path $StagingArea 'SymLinkStorage') -ItemType Directory -Force

                    # The path to the TEMP Supplemental WDAC Policy file
                    [System.IO.FileInfo]$WDACPolicyPathTemp = Join-Path -Path $StagingArea -ChildPath 'TEMP CiPolicy From Logs.xml'

                    # The path to the final Supplemental WDAC Policy file
                    [System.IO.FileInfo]$WDACPolicyPath = Join-Path -Path $StagingArea -ChildPath "CiPolicy From Logs $CurrentDate.xml"

                    # The path to the Kernel protected file hashes WDAC Policy file
                    [System.IO.FileInfo]$WDACPolicyKernelProtectedPath = Join-Path -Path $StagingArea -ChildPath "Kernel Protected Files Hashes $CurrentDate.xml"

                    #Region Kernel-protected-files-automatic-detection-and-allow-rule-creation
                    # This part takes care of Kernel protected files such as the main executable of the games installed through Xbox app
                    # For these files, only Kernel can get their hashes, it passes them to event viewer and we take them from event viewer logs
                    # Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fail and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Checking for Kernel protected files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'ConvertTo-WDACPolicy: Checking for Kernel protected files in the selected logs'

                    # Storing the logs of the kernel protected files
                    [PSCustomObject[]]$KernelProtectedFileLogs = @()

                    # Looping through every file with .exe and .dll extensions to check if they are kernel protected regardless of whether the file exists or not
                    foreach ($Log in $SelectedLogs | Where-Object -FilterScript { [System.IO.Path]::GetExtension($_.'Full Path') -in @('.exe', '.dll') }) {

                        try {
                            # Testing each file to find the protected ones
                            Get-FileHash -Path $Log.'Full Path' -ErrorAction Stop | Out-Null
                        }
                        # If the file is protected, it will throw an exception and the module will continue to the next one
                        # Making sure only the right file is captured by narrowing down the error type.
                        # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
                        catch [System.UnauthorizedAccessException] {
                            $KernelProtectedFileLogs += $Log
                        }
                        catch {
                            Write-Verbose -Message "ConvertTo-WDACPolicy: An unexpected error occurred while checking the file: $($Log.'Full Path')"
                        }
                    }

                    # Only proceed if any kernel protected file(s) were found in any of the selected logs
                    if (($null -ne $KernelProtectedFileLogs) -and ($KernelProtectedFileLogs.count -gt 0)) {

                        Write-Verbose -Message 'ConvertTo-WDACPolicy: The following Kernel protected files were detected, creating allow rules for them:'
                        $KernelProtectedFileLogs | ForEach-Object -Process { Write-Verbose -Message $($_.'File Name') }

                        # Check if any of the kernel-protected files can be allowed by FamilyPackageName
                        [PSCustomObject]$AppxOutput = New-AppxPackageCiPolicy -Logs $KernelProtectedFileLogs -directoryPath $SymLinksStorage

                        if ($null -ne $AppxOutput.PolicyPath) {
                            # Add the path of the Appx package policy file to the array of policy files to merge
                            $PolicyFilesToMerge += $AppxOutput.PolicyPath

                            # Set the flag indicating that there are kernel-protected files in the selected logs
                            [System.Boolean]$HasKernelFiles = $true
                        }

                        # If the New-AppxPackageCiPolicy function returned remaining logs then create allow rules for them using Hash level
                        if (($null -ne $AppxOutput.RemainingLogs) -and ($AppxOutput.RemainingLogs.count -gt 0)) {

                            # Put the Rules and RulesRefs in an empty policy file by extracting the hashes from the logs
                            Write-Verbose -Message "ConvertTo-WDACPolicy: $($AppxOutput.RemainingLogs.count) Kernel protected files were found in the selected logs that did not have the PackageFamilyName property or the app is not installed on the system, creating allow rules for them using Hash level"

                            New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $AppxOutput.RemainingLogs) -RuleRefsContent (Get-RuleRefs -HashesArray $AppxOutput.RemainingLogs) | Out-File -FilePath $WDACPolicyKernelProtectedPath -Force

                            # Add the path of the Kernel protected files Hashes policy file to the array of policy files to merge
                            $PolicyFilesToMerge += $WDACPolicyKernelProtectedPath

                            # Set the flag indicating that there are kernel-protected files in the selected logs
                            [System.Boolean]$HasKernelFiles = $true
                        }
                        else {
                            Write-Verbose -Message 'ConvertTo-WDACPolicy: All kernel protected files were allowed using their PackageFamilyName property'
                        }
                    }
                    else {
                        Write-Verbose -Message 'ConvertTo-WDACPolicy: No Kernel protected files were found in any of the selected logs'
                    }

                    [System.UInt64]$LogCountBeforeRemovingKernelProtectedFiles = $SelectedLogs.Count

                    # Remove the logs of the Kernel protected files from the selected logs since they cannot be scanned with New-CIPolicy cmdlet
                    [PSCustomObject[]]$SelectedLogs = $SelectedLogs | Where-Object -FilterScript { $KernelProtectedFileLogs -notcontains $_ }

                    Write-Verbose -Message "ConvertTo-WDACPolicy: The number of logs before removing the Kernel protected files: $LogCountBeforeRemovingKernelProtectedFiles and after: $($SelectedLogs.Count). There were $($KernelProtectedFileLogs.Count) Kernel protected files."
                    #Endregion Kernel-protected-files-automatic-detection-and-allow-rule-creation

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Processing the logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # If there are still logs after removing the kernel protected files, then scan them
                    if (($null -ne $SelectedLogs) -and ($SelectedLogs.Count -gt 0)) {

                        #Region Main Policy Creation

                        Write-Verbose -Message 'ConvertTo-WDACPolicy: Creating symbolic links to the non-kernel-protected files in the logs'
                        Foreach ($File in $SelectedLogs) {
                            New-Item -ItemType SymbolicLink -Path (Join-Path -Path $SymLinksStorage -ChildPath $File.'File Name') -Target $File.'Full Path' -Force | Out-Null
                        }

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        [System.Collections.Hashtable]$CiPolicyScanHashTable = @{
                            FilePath               = $WDACPolicyPathTemp
                            ScanPath               = $SymLinksStorage
                            Level                  = 'WHQLFilePublisher'
                            MultiplePolicyFormat   = $true
                            UserWriteablePaths     = $true
                            AllowFileNameFallbacks = $true
                        }
                        # Only scan UserPEs if the KernelModeOnly switch is not used
                        if (!$KernelModeOnly) { $CiPolicyScanHashTable['UserPEs'] = $true }

                        # Set the Fallback property to 'None' if the KernelModeOnly switch is used, otherwise set it to 'FilePublisher' and 'Hash'
                        $CiPolicyScanHashTable['Fallback'] = $KernelModeOnly ? 'None' : ('FilePublisher', 'Hash')

                        Write-Verbose -Message 'ConvertTo-WDACPolicy: Scanning the files in the selected event logs with the following parameters:'
                        if ($Verbose) { $CiPolicyScanHashTable }

                        New-CIPolicy @CiPolicyScanHashTable

                        # Add the path of the TEMP WDAC Policy file as the 1st element to the policy files to merge array
                        $PolicyFilesToMerge = @($WDACPolicyPathTemp) + $PolicyFilesToMerge

                        # Set the flag indicating that there are normal files in the selected logs
                        [System.Boolean]$HasNormalFiles = $true

                        #Endregion Main Policy Creation
                    }

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Generating the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # If there are only kernel-protected files in the selected logs
                    if (($HasKernelFiles -eq $true) -and ($HasNormalFiles -eq $false)) {
                        Write-Verbose -Message 'ConvertTo-WDACPolicy: There are only kernel-protected files in the selected logs'
                        Merge-CIPolicy -PolicyPaths $PolicyFilesToMerge -OutputFilePath $WDACPolicyPath | Out-Null
                    }
                    # If there are only normal files in the selected logs
                    elseif (($HasKernelFiles -eq $false) -and ($HasNormalFiles -eq $true)) {
                        Write-Verbose -Message 'ConvertTo-WDACPolicy: There are only normal files in the selected logs'

                        # Using merge on a single policy takes care of any possible orphaned rules or file attributes
                        Merge-CIPolicy -PolicyPaths $WDACPolicyPathTemp -OutputFilePath $WDACPolicyPath | Out-Null
                    }
                    # If there are both kernel-protected and normal files in the selected logs
                    elseif (($HasKernelFiles -eq $true) -and ($HasNormalFiles -eq $true)) {
                        Write-Verbose -Message 'ConvertTo-WDACPolicy: There are both kernel-protected and normal files in the selected logs'
                        Merge-CIPolicy -PolicyPaths $PolicyFilesToMerge -OutputFilePath $WDACPolicyPath | Out-Null
                    }
                    # If there are no files in the selected logs
                    else {
                        Write-ColorfulText -Color HotPink -InputText 'No logs were selected to create a WDAC policy from. Exiting...'
                        return
                    }

                    #Region Base To Supplemental Policy Association and Deployment

                    Switch ($True) {

                        { $null -ne $BasePolicyFile } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Associating the Supplemental policy with the user input base policy'

                            # Objectify the user input base policy file to extract its Base policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName "Supplemental Policy from event logs - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $InputXMLObj.SiPolicy.BasePolicyID -ResetPolicyID
                            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

                            # Configure policy rule options
                            Set-CiRuleOptions -FilePath $WDACPolicyPath -Template Supplemental

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Copy-Item -Path $WDACPolicyPath -Destination $UserConfigDir -Force

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $WDACPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") -json | Out-Null
                            }
                        }

                        { $null -ne $BasePolicyGUID } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Assigning the user input GUID to the base policy ID of the supplemental policy'

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName "Supplemental Policy from event logs - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $BasePolicyGUID -ResetPolicyID
                            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

                            # Configure policy rule options
                            Set-CiRuleOptions -FilePath $WDACPolicyPath -Template Supplemental

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Copy-Item -Path $WDACPolicyPath -Destination $UserConfigDir -Force

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $WDACPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") -json | Out-Null
                            }
                        }

                        { $null -ne $PolicyToAddLogsTo } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Adding the logs to the policy that user selected'

                            # Objectify the user input policy file to extract its policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $PolicyToAddLogsTo)

                            Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName "Supplemental Policy from event logs - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID | Out-Null

                            # Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
                            Set-CiRuleOptions -FilePath $WDACPolicyPath -RemoveAll

                            Merge-CIPolicy -PolicyPaths $PolicyToAddLogsTo, $WDACPolicyPath -OutputFilePath $PolicyToAddLogsTo | Out-Null

                            # Set HVCI to Strict
                            Set-HVCIOptions -Strict -FilePath $PolicyToAddLogsTo

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $PolicyToAddLogsTo -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the policy that user selected to add the logs to'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip") -json | Out-Null
                            }
                        }
                    }

                    #Endregion Base To Supplemental Policy Association and Deployment
                }
                'MDEAdvancedHunting' {

                    <#
                    ALL OF THE FUNCTIONS THAT PERFORM DATA MERGING ARE CREATED TO HANDLE MDE ADVANCED HUNTING DATA ONLY
                    SO NO DENIED SIGNERS OR DENY RULES WHATSOEVER
                    FOR MERGING WITH OTHER POLICIES, MERGE-CIPOLICY CMDLET SHOULD BE USED
                    AT LEAST UNTIL THE NECESSARY FUNCTIONALITY IS ADDED TO THE MERGER FUNCTIONS
                    #>

                    # The total number of the main steps for the progress bar to render
                    [System.UInt16]$TotalSteps = 9
                    [System.UInt16]$CurrentStep = 0

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Optimizing the MDE CSV data' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Optimizing the MDE CSV data'
                    [System.Collections.Hashtable[]]$OptimizedCSVData = Optimize-MDECSVData -CSVPath $MDEAHLogs -StagingArea $StagingArea

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Identifying the correlated data in the MDE CSV data' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Identifying the correlated data in the MDE CSV data'

                    if (($null -eq $OptimizedCSVData) -or ($OptimizedCSVData.Count -eq 0)) {
                        Write-ColorfulText -Color HotPink -InputText 'No valid MDE Advanced Hunting logs available. Exiting...'
                        return
                    }

                    if ($TimeSpan) {
                        [System.Collections.Hashtable]$EventPackageCollections = Compare-CorrelatedData -OptimizedCSVData $OptimizedCSVData -StagingArea $StagingArea -StartTime $StartTime -PolicyNamesToFilter:$FilterByPolicyNames -LogType:$LogType
                    }
                    else {
                        [System.Collections.Hashtable]$EventPackageCollections = Compare-CorrelatedData -OptimizedCSVData $OptimizedCSVData -StagingArea $StagingArea -PolicyNamesToFilter:$FilterByPolicyNames -LogType:$LogType
                    }

                    # Selecting all of the properties of each log to be displayed
                    $MDEAHLogsToDisplay = $EventPackageCollections.Values -as [PSCustomObject] | Select-Object -Property *

                    # If the KernelModeOnly switch is used, then filter the logs by the 'SiSigningScenario' property
                    if ($KernelModeOnly) {
                        $MDEAHLogsToDisplay = $MDEAHLogsToDisplay | Where-Object -FilterScript { $_.'SiSigningScenario' -eq '0' }
                    }

                    if (($null -eq $MDEAHLogsToDisplay) -or ($MDEAHLogsToDisplay.Count -eq 0)) {
                        Write-ColorfulText -Color HotPink -InputText 'No MDE Advanced Hunting logs available based on the selected filters. Exiting...'
                        return
                    }

                    #Region Out-GridView properties visibility settings

                    # If the ExtremeVisibility switch is used, then display all the properties of the logs without any filtering
                    if (-NOT $ExtremeVisibility) {
                        Set-LogPropertiesVisibility -LogType MDEAH -EventsToDisplay $MDEAHLogsToDisplay
                    }

                    #Endregion Out-GridView properties visibility settings

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Displaying the MDE Advanced Hunting logs in a GUI' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Displaying the MDE Advanced Hunting logs in a GUI'
                    [PSCustomObject[]]$SelectMDEAHLogs = $MDEAHLogsToDisplay | Out-GridView -OutputMode Multiple -Title "Displaying $($MDEAHLogsToDisplay.count) Microsoft Defender for Endpoint Advanced Hunting Logs"

                    if (($null -eq $SelectMDEAHLogs) -or ($SelectMDEAHLogs.Count -eq 0)) {
                        Write-ColorfulText -Color HotPink -InputText 'No MDE Advanced Hunting logs were selected to create a WDAC policy from. Exiting...'
                        return
                    }

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Preparing an empty policy to save the logs to' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Define the path where the final MDE AH XML policy file will be saved
                    [System.IO.FileInfo]$OutputPolicyPathMDEAH = Join-Path -Path $StagingArea -ChildPath "MDE Advanced Hunting Policy $CurrentDate.xml"

                    Write-Verbose -Message 'Copying the template policy to the staging area'
                    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $OutputPolicyPathMDEAH -Force

                    Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
                    Clear-CiPolicy_Semantic -Path $OutputPolicyPathMDEAH

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Building the Signer and Hash objects from the selected MDE AH logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Building the Signer and Hash objects from the selected MDE AH logs'
                    [PSCustomObject]$DataToUseForBuilding = Build-SignerAndHashObjects -Data $SelectMDEAHLogs -IncomingDataType MDEAH

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Creating rules for different levels' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    if ($Null -ne $DataToUseForBuilding.FilePublisherSigners -and $DataToUseForBuilding.FilePublisherSigners.Count -gt 0) {
                        Write-Verbose -Message 'Creating File Publisher Level rules'
                        New-FilePublisherLevelRules -FilePublisherSigners $DataToUseForBuilding.FilePublisherSigners -XmlFilePath $OutputPolicyPathMDEAH
                    }
                    if ($Null -ne $DataToUseForBuilding.PublisherSigners -and $DataToUseForBuilding.PublisherSigners.Count -gt 0) {
                        Write-Verbose -Message 'Creating Publisher Level rules'
                        New-PublisherLevelRules -PublisherSigners $DataToUseForBuilding.PublisherSigners -XmlFilePath $OutputPolicyPathMDEAH
                    }
                    if ($Null -ne $DataToUseForBuilding.CompleteHashes -and $DataToUseForBuilding.CompleteHashes.Count -gt 0) {
                        Write-Verbose -Message 'Creating Hash Level rules'
                        New-HashLevelRules -Hashes $DataToUseForBuilding.CompleteHashes -XmlFilePath $OutputPolicyPathMDEAH
                    }

                    # MERGERS

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Merging the Hash Level rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Merging the Hash Level rules'
                    Remove-AllowElements_Semantic -Path $OutputPolicyPathMDEAH
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $OutputPolicyPathMDEAH

                    # Remove-UnreferencedFileRuleRefs -xmlFilePath $OutputPolicyPathMDEAH

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Merging the Signer Level rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Merging the Signer Level rules'
                    Remove-DuplicateFileAttrib_Semantic -XmlFilePath $OutputPolicyPathMDEAH

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Finishing up the merge operation' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    <#
                        Improvement suggestion for the Merge-Signers_Semantic function
                        When an orphan CiSigner is found, it is currently being removed from the <CiSigners> node

                        Suggestion:
                        Implement an extra check to go through all User-Mode Signers and make sure they each have a corresponding CiSigner
                        They already get a CiSigner automatically during build operations, but this check is just extra in case the policy was intentionally modified by the user!

                        Use Case:
                        User intentionally modifies one of the IDs of the CiSigners, but forgets to update the corresponding User-Mode Signer ID, AllowedSigner ID and more.
                    #>

                    # 2 passes are necessary
                    Merge-Signers_Semantic -XmlFilePath $OutputPolicyPathMDEAH
                    Merge-Signers_Semantic -XmlFilePath $OutputPolicyPathMDEAH

                    # This function runs twice, once for signed data and once for unsigned data
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $OutputPolicyPathMDEAH

                    # UNUSED FUNCTIONS - Their jobs have been replaced by semantic functions
                    # Keeping them here for reference

                    # Remove-OrphanAllowedSignersAndCiSigners_IDBased -Path $OutputPolicyPathMDEAH
                    # Remove-DuplicateAllowedSignersAndCiSigners_IDBased -Path $OutputPolicyPathMDEAH
                    # Remove-DuplicateFileAttrib_IDBased -XmlFilePath $OutputPolicyPathMDEAH
                    # Remove-DuplicateAllowAndFileRuleRefElements_IDBased -XmlFilePath $OutputPolicyPathMDEAH
                    # Remove-DuplicateFileAttrib_Semantic -XmlFilePath $OutputPolicyPathMDEAH
                    # Remove-DuplicateFileAttribRef_IDBased -XmlFilePath $OutputPolicyPathMDEAH -Verbose

                    #Region Base To Supplemental Policy Association and Deployment

                    Switch ($True) {

                        { $null -ne $BasePolicyFile } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Associating the Supplemental policy with the user input base policy'

                            # Objectify the user input base policy file to extract its Base policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathMDEAH -PolicyName "Supplemental Policy from MDE Advanced Hunting - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $InputXMLObj.SiPolicy.BasePolicyID -ResetPolicyID
                            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

                            # Configure policy rule options
                            Set-CiRuleOptions -FilePath $OutputPolicyPathMDEAH -Template Supplemental

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Copy-Item -Path $OutputPolicyPathMDEAH -Destination $UserConfigDir -Force

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathMDEAH -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") -json | Out-Null
                            }
                        }

                        { $null -ne $BasePolicyGUID } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Assigning the user input GUID to the base policy ID of the supplemental policy'

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathMDEAH -PolicyName "Supplemental Policy from MDE Advanced Hunting - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $BasePolicyGUID -ResetPolicyID
                            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

                            # Configure policy rule options
                            Set-CiRuleOptions -FilePath $OutputPolicyPathMDEAH -Template Supplemental

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Copy-Item -Path $OutputPolicyPathMDEAH -Destination $UserConfigDir -Force

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathMDEAH -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") -json | Out-Null
                            }
                        }

                        { $null -ne $PolicyToAddLogsTo } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Adding the logs to the policy that user selected'

                            # Objectify the user input policy file to extract its policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $PolicyToAddLogsTo)

                            Set-CIPolicyIdInfo -FilePath $OutputPolicyPathMDEAH -PolicyName "Supplemental Policy from MDE Advanced Hunting - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID | Out-Null

                            # Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
                            Set-CiRuleOptions -FilePath $OutputPolicyPathMDEAH -RemoveAll

                            Merge-CIPolicy -PolicyPaths $PolicyToAddLogsTo, $OutputPolicyPathMDEAH -OutputFilePath $PolicyToAddLogsTo | Out-Null

                            # Set HVCI to Strict
                            Set-HVCIOptions -Strict -FilePath $PolicyToAddLogsTo

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $PolicyToAddLogsTo -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the policy that user selected to add the MDE AH logs to'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip") -json | Out-Null
                            }
                        }

                        Default {
                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Set-CiRuleOptions -FilePath $OutputPolicyPathMDEAH -Template Supplemental
                            Copy-Item -Path $OutputPolicyPathMDEAH -Destination $UserConfigDir -Force
                        }
                    }

                    #Endregion Base To Supplemental Policy Association and Deployment
                }
                'EVTXFiles' {

                    # The total number of the main steps for the progress bar to render
                    [System.UInt16]$TotalSteps = 6
                    [System.UInt16]$CurrentStep = 0

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Processing the selected Evtx files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PolicyName:$FilterByPolicyNames -Date:$StartTime -Type:$LogType -LogSource EVTXFiles -EVTXFilePaths $EVTXLogs
                    [PSCustomObject[]]$EventsToDisplay = Select-LogProperties -Logs $EventsToDisplay

                    # If the KernelModeOnly switch is used, then filter the events by the 'Requested Signing Level' property
                    if ($KernelModeOnly) {
                        $EventsToDisplay = $EventsToDisplay | Where-Object -FilterScript { $_.'SI Signing Scenario' -eq 'Kernel-Mode' }
                    }

                    if (($null -eq $EventsToDisplay) -and ($EventsToDisplay.Count -eq 0)) {
                        Write-ColorfulText -Color HotPink -InputText 'No logs were found to display based on the current filters. Exiting...'
                        return
                    }

                    #Region Out-GridView properties visibility settings

                    # If the ExtremeVisibility switch is used, then display all the properties of the logs without any filtering
                    if (-NOT $ExtremeVisibility) {
                        Set-LogPropertiesVisibility -LogType Evtx/Local -EventsToDisplay $EventsToDisplay
                    }

                    #Endregion Out-GridView properties visibility settings

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Displaying the logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Display the logs in a grid view using the build-in cmdlet
                    $SelectedLogs = $EventsToDisplay | Out-GridView -OutputMode Multiple -Title "Displaying $($EventsToDisplay.count) $LogType Code Integrity Logs"

                    Write-Verbose -Message "ConvertTo-WDACPolicy: Selected logs count: $($SelectedLogs.count)"

                    if (($null -eq $SelectedLogs) -or ( $SelectedLogs.Count -eq 0)) {
                        Write-ColorfulText -Color HotPink -InputText 'No logs were selected to create a WDAC policy from. Exiting...'
                        return
                    }

                    # Define the path where the final Evtx XML policy file will be saved
                    [System.IO.FileInfo]$OutputPolicyPathEVTX = Join-Path -Path $StagingArea -ChildPath "Policy from Evtx files $CurrentDate.xml"

                    Write-Verbose -Message 'Copying the template policy to the staging area'
                    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $OutputPolicyPathEVTX -Force

                    Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
                    Clear-CiPolicy_Semantic -Path $OutputPolicyPathEVTX

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Building Signers and file rule' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Building the Signer and Hash objects from the selected Evtx logs'
                    [PSCustomObject]$DataToUseForBuilding = Build-SignerAndHashObjects -Data $SelectedLogs -IncomingDataType EVTX

                    if ($Null -ne $DataToUseForBuilding.FilePublisherSigners -and $DataToUseForBuilding.FilePublisherSigners.Count -gt 0) {
                        Write-Verbose -Message 'Creating File Publisher Level rules'
                        New-FilePublisherLevelRules -FilePublisherSigners $DataToUseForBuilding.FilePublisherSigners -XmlFilePath $OutputPolicyPathEVTX
                    }
                    if ($Null -ne $DataToUseForBuilding.PublisherSigners -and $DataToUseForBuilding.PublisherSigners.Count -gt 0) {
                        Write-Verbose -Message 'Creating Publisher Level rules'
                        New-PublisherLevelRules -PublisherSigners $DataToUseForBuilding.PublisherSigners -XmlFilePath $OutputPolicyPathEVTX
                    }
                    if ($Null -ne $DataToUseForBuilding.CompleteHashes -and $DataToUseForBuilding.CompleteHashes.Count -gt 0) {
                        Write-Verbose -Message 'Creating Hash Level rules'
                        New-HashLevelRules -Hashes $DataToUseForBuilding.CompleteHashes -XmlFilePath $OutputPolicyPathEVTX
                    }

                    # MERGERS

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Performing merge operations' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Merging the Hash Level rules'
                    Remove-AllowElements_Semantic -Path $OutputPolicyPathEVTX
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $OutputPolicyPathEVTX

                    # Remove-UnreferencedFileRuleRefs -xmlFilePath $OutputPolicyPathEVTX

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Making sure there are no duplicates' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Merging the Signer Level rules'
                    Remove-DuplicateFileAttrib_Semantic -XmlFilePath $OutputPolicyPathEVTX

                    # 2 passes are necessary
                    Merge-Signers_Semantic -XmlFilePath $OutputPolicyPathEVTX
                    Merge-Signers_Semantic -XmlFilePath $OutputPolicyPathEVTX

                    # This function runs twice, once for signed data and once for unsigned data
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $OutputPolicyPathEVTX

                    #Region Base To Supplemental Policy Association and Deployment

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Generating the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Switch ($True) {

                        { $null -ne $BasePolicyFile } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Associating the Supplemental policy with the user input base policy'

                            # Objectify the user input base policy file to extract its Base policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathEVTX -PolicyName "Supplemental Policy from Evtx files - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $InputXMLObj.SiPolicy.BasePolicyID -ResetPolicyID
                            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

                            # Configure policy rule options
                            Set-CiRuleOptions -FilePath $OutputPolicyPathEVTX -Template Supplemental

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Copy-Item -Path $OutputPolicyPathEVTX -Destination $UserConfigDir -Force

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathEVTX -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") -json | Out-Null
                            }
                        }

                        { $null -ne $BasePolicyGUID } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Assigning the user input GUID to the base policy ID of the supplemental policy'

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathEVTX -PolicyName "Supplemental Policy from Evtx files - $(Get-Date -Format 'MM-dd-yyyy')" -SupplementsBasePolicyID $BasePolicyGUID -ResetPolicyID
                            [System.String]$SupplementalPolicyID = $SupplementalPolicyID.Substring(11)

                            # Configure policy rule options
                            Set-CiRuleOptions -FilePath $OutputPolicyPathEVTX -Template Supplemental

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Copy-Item -Path $OutputPolicyPathEVTX -Destination $UserConfigDir -Force

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathEVTX -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the Supplemental policy'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip") -json | Out-Null
                            }
                        }

                        { $null -ne $PolicyToAddLogsTo } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Adding the logs to the policy that user selected'

                            # Objectify the user input policy file to extract its policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $PolicyToAddLogsTo)

                            Set-CIPolicyIdInfo -FilePath $OutputPolicyPathEVTX -PolicyName "Supplemental Policy from Evtx files - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID | Out-Null

                            # Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
                            Set-CiRuleOptions -FilePath $OutputPolicyPathEVTX -RemoveAll

                            Merge-CIPolicy -PolicyPaths $PolicyToAddLogsTo, $OutputPolicyPathEVTX -OutputFilePath $PolicyToAddLogsTo | Out-Null

                            # Set HVCI to Strict
                            Set-HVCIOptions -Strict -FilePath $PolicyToAddLogsTo

                            if ($Deploy) {
                                ConvertFrom-CIPolicy -XmlFilePath $PolicyToAddLogsTo -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip") | Out-Null

                                Write-Verbose -Message 'ConvertTo-WDACPolicy: Deploying the policy that user selected to add the Evtx logs to'

                                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip") -json | Out-Null
                            }
                        }

                        Default {
                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Copying the policy file to the User Config directory'
                            Set-CiRuleOptions -FilePath $OutputPolicyPathEVTX -Template Supplemental
                            Copy-Item -Path $OutputPolicyPathEVTX -Destination $UserConfigDir -Force
                        }
                    }

                    #Endregion Base To Supplemental Policy Association and Deployment

                }
            }
        }
        Finally {
            Write-Progress -Id 30 -Activity 'Complete.' -Completed
            Write-Progress -Id 31 -Activity 'Complete.' -Completed
            Write-Progress -Id 32 -Activity 'Complete.' -Completed

            if (-NOT $Debug) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    This is a multi-purpose cmdlet that offers a wide range of functionalities that can either be used separately or mixed together for very detailed and specific tasks.
    It currently supports Code Integrity and AppLocker logs from the following sources: Local Event logs, Evtx log files and Microsoft Defender for Endpoint Advanced Hunting results.

    The cmdlet displays the logs in a GUI and allows the user to select the logs to be processed further.

    The logs can be filtered based on many criteria using the available parameters.

    The output of this cmdlet is a Supplemental Application Control (WDAC) policy.
    Based on the input parameters, it can be associated with a base policy or merged with an existing Base or Supplemental policy.
.DESCRIPTION
   The cmdlet can be used for local and remote systems. You can utilize this cmdlet to create Application Control for Business policies from MDE Advanced Hunting and then deploy them using Microsoft Intune to your endpoints.

   You can utilize this cmdlet to use the evtx log files you aggregated from your endpoints and create a WDAC policy from them.

   This offers scalability and flexibility in managing your security policies.
.PARAMETER PolicyToAddLogsTo
    The policy to add the selected logs to, it can either be a base or supplemental policy.
.PARAMETER BasePolicyFile
    The base policy file to associate the supplemental policy with
.PARAMETER BasePolicyGUID
    The GUID of the base policy to associate the supplemental policy with
.PARAMETER FilterByPolicyNames
   The names of the policies to filter the logs by.
   Supports auto-completion, press TAB key to view the list of the deployed base policy names to choose from.
   It will not display the policies that are already selected on the command line.
   You can manually enter the name of the policies that are no longer available on the system or are from remote systems in case of MDE Advanced Hunting logs.
.PARAMETER Source
    The source of the logs: Local Event logs (LocalEventLogs), Microsoft Defender for Endpoint Advanced Hunting results (MDEAdvancedHunting) or EVTX files (EVTXFiles).
    Supports validate set.
.PARAMETER MDEAHLogs
    The path(s) to use MDE AH CSV files.
    This is a dynamic parameter and will only be available if the Source parameter is set to MDEAdvancedHunting.
.PARAMETER EVTXLogs
    The path(s) to use EVTX files.
    This is a dynamic parameter and will only be available if the Source parameter is set to EVTXFiles.
.PARAMETER KernelModeOnly
    If used, will filter the logs by including only the Kernel-Mode logs. You can use this parameter to easily create Supplemental policies for Strict Kernel-Mode WDAC policy.
    More info available here: https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-policy-for-BYOVD-Kernel-mode-only-protection
.PARAMETER LogType
    The type of logs to display: Audit or Blocked, the default is Audit.
.PARAMETER TimeSpan
    The unit of time to use when filtering the logs by the time.
    The allowed values are: Minutes, Hours, Days
.PARAMETER TimeSpanAgo
    The number of the selected time unit to go back in time from the current time.
.PARAMETER Deploy
    If used, will deploy the policy on the system
.PARAMETER ExtremeVisibility
    If used, will display all the properties of the logs without any filtering.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/ConvertTo-WDACPolicy
.INPUTS
    System.IO.FileInfo
    System.Guid
    System.String
    System.String[]
    System.UInt64
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
.EXAMPLE
    ConvertTo-WDACPolicy -PolicyToAddLogsTo "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml" -Verbose

    This example will display the Code Integrity and AppLocker logs in a GUI and allow the user to select the logs to add to the specified policy file.
.EXAMPLE
    ConvertTo-WDACPolicy -Verbose -BasePolicyGUID '{ACE9058C-8A24-47F4-86F0-A33FAB5073E3}'

    This example will display the Code Integrity and AppLocker logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy GUID.
.EXAMPLE
    ConvertTo-WDACPolicy -BasePolicyFile "C:\Users\Admin\AllowMicrosoftPlusBlockRules.xml"

    This example will display the Code Integrity and AppLocker logs in a GUI and allow the user to select the logs to create a new supplemental policy and associate it with the specified base policy file.
.EXAMPLE
    ConvertTo-WDACPolicy

    This example will display the Code Integrity and AppLocker logs in a GUI and takes no further action.
.EXAMPLE
    ConvertTo-WDACPolicy -FilterByPolicyNames 'VerifiedAndReputableDesktopFlightSupplemental','WindowsE_Lockdown_Flight_Policy_Supplemental' -Verbose

    This example will filter the Code Integrity and AppLocker logs by the specified policy names and display them in a GUI. It will also display verbose messages on the console.
.EXAMPLE
    ConvertTo-WDACPolicy -FilterByPolicyNames 'Microsoft Windows Driver Policy - Enforced' -TimeSpan Minutes -TimeSpanAgo 10

    This example will filter the local Code Integrity and AppLocker logs by the specified policy name and the number of minutes ago from the current time and display them in a GUI.
    So, it will display the logs that are 10 minutes old and are associated with the specified policy name.
.EXAMPLE
    ConvertTo-WDACPolicy -BasePolicyFile "C:\Program Files\WDACConfig\DefaultWindowsPlusBlockRules.xml" -Source MDEAdvancedHunting -MDEAHLogs "C:\Users\Admin\Downloads\New query.csv" -Deploy -TimeSpan Days -TimeSpanAgo 2

    This example will create a new supplemental policy from the selected MDE Advanced Hunting logs and associate it with the specified base policy file and it will deploy it on the system.
    The displayed logs will be from the last 2 days. You will be able to select the logs to create the policy from in the GUI.
.EXAMPLE
ConvertTo-WDACPolicy -BasePolicyGUID '{89CD611D-5557-4833-B73D-716B979AEE3D}' -Source EVTXFiles -EVTXLogs "C:\Users\HotCakeX\App Locker logs.evtx","C:\Users\HotCakeX\Code Integrity LOGS.evtx"

This example will create a new supplemental policy from the selected EVTX files and associate it with the specified base policy GUID.

.EXTERNALHELP ..\Help\ConvertTo-WDACPolicy.xml
#>

}
# Importing argument completer ScriptBlocks
. "$ModuleRootPath\CoreExt\ArgumentCompleters.ps1"

Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'PolicyToAddLogsTo' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'BasePolicyFile' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC8fVmhmqw1Nh91
# ot+/2837+pJo8C2smSDKnP7atOKnD6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgOd1ijymTYbmEoZDbYnglGGPQS3gm8hq2fjIBL7Gqna8wDQYJKoZIhvcNAQEB
# BQAEggIAO+TeYOqiftPiqjfzPpDTXv021POvpbx7En1RINdDwVzsMToqu1PbBnKd
# uEzeDYwQtug2LEDkXJH6K7M6XKbUqeulCxUMPH0q5FRSbsqM5EDjjmJv+Cm5vpN2
# kb0GiufxGJvUChHthm8Es0taN7FnEEmMSBwd4A3bTGBrZ1NYBddC0mWT6yfZrntL
# VBKdMEhJIW0ixS1gDQ2WwiaSiViFiogwPoWtSjUn1kIYHToN+kkbMiAc7HjQkfX7
# +Bw5xIZLh4R8ZqL+e0qKNuCK1UAYcZVqBWwW1KVR2dxevAblC4GfLkeDpJzYByoR
# SmSLzjj9o8HudlNXG1vLdf1JxUjLISlguCcx94Wjr80AkX8c1vNQec/qBYKrFJqu
# b0XEbEQdtVggFs7POypGLQYCtZ0p6zw0aIROY9M565CkMAOznR9jgIP+GeqfiVaf
# MIaw7ZCIXqz8HzBioXuCEUhcRkjrJRna3mh+ughvFhazccPZtTA9fc+hwriDlIp+
# Ls81h6PpDMbo2fXVlCUxCctVi7PJnfuUaoWBelXjzp8ihZkE5r3mT1UF6HSaARgR
# qPDaAu4Y5/TMArMSLAqzHvobNhqquF0C+jLQDxnpeYgLsBNPQ0NYZ/XZwhy0694M
# sILHpwj/249UQDTpkb+e8pCGJAkGUON9zKi4IJ6EPjK5wkUQ3vs=
# SIG # End signature block
