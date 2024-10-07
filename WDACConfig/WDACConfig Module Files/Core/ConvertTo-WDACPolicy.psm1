Function ConvertTo-WDACPolicy {
    [CmdletBinding(
        DefaultParameterSetName = 'All'
    )]
    param(
        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [Alias('AddLogs')]
        [ValidateScript({ [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) })]
        [Parameter(Mandatory = $false, ParameterSetName = 'In-Place Upgrade')]
        [System.IO.FileInfo]$PolicyToAddLogsTo,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [Alias('BaseFile')]
        [ValidateScript({ [WDACConfig.CiPolicyTest]::TestCiPolicy($_, $null) })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy File Association')]
        [System.IO.FileInfo]$BasePolicyFile,

        [Alias('Lvl')]
        [ValidateSet('Auto', 'FilePublisher', 'Publisher', 'Hash')]
        [Parameter(Mandatory = $false)][System.String]$Level = 'Auto',

        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $fakeBoundParameters)

                [System.String[]]$PolicyGUIDs = [WDACConfig.CiToolHelper]::GetPolicies($false, $true, $false).PolicyID

                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                foreach ($Item in $PolicyGUIDs) {
                    if ($Item -notin $Existing) {
                        "'{0}'" -f $Item
                    }
                }
            })]
        [Parameter(Mandatory = $false, ParameterSetName = 'Base-Policy GUID Association')]
        [Alias('BaseGUID')]
        [System.Guid]$BasePolicyGUID,

        [Alias('Name')]
        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [Parameter(Mandatory = $false)][System.String]$SuppPolicyName,

        [Alias('Src')]
        [ValidateSet('MDEAdvancedHunting', 'LocalEventLogs', 'EVTXFiles')]
        [Parameter(Mandatory = $false)][System.String]$Source = 'LocalEventLogs',

        [ArgumentCompleter({
                param($CommandName, $ParameterName, $WordToComplete, $CommandAst, $FakeBoundParameters)

                [System.String[]]$Policies = [WDACConfig.CiToolHelper]::GetPolicies($true, $true, $false).FriendlyName

                $Existing = $CommandAst.FindAll({
                        $args[0] -is [System.Management.Automation.Language.StringConstantExpressionAst]
                    }, $false).Value

                foreach ($Policy in $Policies) {
                    if ($Policy -notin $Existing) {
                        "'{0}'" -f $Policy
                    }
                }
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
        [System.Management.Automation.ValidateSetAttribute]$LogType_ValidateSetAttrib = New-Object -TypeName System.Management.Automation.ValidateSetAttribute('Audit', 'Blocked', 'All')
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
    Begin {
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)

        [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Importing the required sub-modules')
        # Defining list of generic modules required for this cmdlet to import
        [System.String[]]$ModulesToImport = @(
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Receive-CodeIntegrityLogs.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Set-LogPropertiesVisibility.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Select-LogProperties.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Test-KernelProtectedFiles.psm1"
        )
        # Add XML Ops module to the list of modules to import
        $ModulesToImport += ([WDACConfig.FileUtility]::GetFilesFast("$([WDACConfig.GlobalVars]::ModuleRootPath)\XMLOps", $null, '.psm1')).FullName
        Import-Module -FullyQualifiedName $ModulesToImport -Force

        # Since Dynamic parameters are only available in the parameter dictionary, we have to access them using $PSBoundParameters or assign them manually to another variable in the function's scope
        New-Variable -Name 'TimeSpanAgo' -Value $PSBoundParameters['TimeSpanAgo'] -Force
        New-Variable -Name 'MDEAHLogs' -Value $PSBoundParameters['MDEAHLogs'] -Force
        New-Variable -Name 'EVTXLogs' -Value $PSBoundParameters['EVTXLogs'] -Force
        New-Variable -Name 'KernelModeOnly' -Value $PSBoundParameters['KernelModeOnly'] -Force
        New-Variable -Name 'LogType' -Value ($PSBoundParameters['LogType'] ?? 'All') -Force
        New-Variable -Name 'Deploy' -Value $PSBoundParameters['Deploy'] -Force
        New-Variable -Name 'ExtremeVisibility' -Value $PSBoundParameters['ExtremeVisibility'] -Force
        New-Variable -Name 'SkipVersionCheck' -Value $PSBoundParameters['SkipVersionCheck'] -Force

        if (-NOT $SkipVersionCheck) { Update-WDACConfigPSModule -InvocationStatement $MyInvocation.Statement }

        # Defining a staging area for the current
        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('ConvertTo-WDACPolicy')

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

                    # Define the policy name if it wasn't provided by the user
                    [System.String]$SuppPolicyName = $PSBoundParameters['SuppPolicyName'] ?? "Supplemental Policy from event logs - $CurrentDate"

                    # The path to the final Supplemental WDAC Policy file
                    [System.IO.FileInfo]$WDACPolicyPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

                    # The path to the temp WDAC Policy file
                    [System.IO.FileInfo]$WDACPolicyPathTEMP = Join-Path -Path $StagingArea -ChildPath "TEMP $SuppPolicyName.xml"

                    # The path to the Kernel protected files WDAC Policy file
                    [System.IO.FileInfo]$WDACPolicyKernelProtectedPath = Join-Path -Path $StagingArea -ChildPath "Kernel Protected Files $SuppPolicyName.xml"

                    # The paths to the policy files to be merged together to produce the final Supplemental policy
                    $PolicyFilesToMerge = New-Object -TypeName System.Collections.Generic.List[System.IO.FileInfo]

                    # The total number of the main steps for the progress bar to render
                    [System.UInt16]$TotalSteps = 6
                    [System.UInt16]$CurrentStep = 0

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity "Collecting $LogType events" -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    if ($null -ne $StartTime -and $StartTime -is [System.DateTime]) {
                        [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PostProcessing OnlyExisting -PolicyName:$FilterByPolicyNames -Date $StartTime -Type:$LogType
                    }
                    else {
                        [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PostProcessing OnlyExisting -PolicyName:$FilterByPolicyNames -Type:$LogType
                    }

                    [PSCustomObject[]]$EventsToDisplay = Select-LogProperties -Logs $EventsToDisplay

                    # If the KernelModeOnly switch is used, then filter the events by the 'Requested Signing Level' property
                    if ($KernelModeOnly) {
                        $EventsToDisplay = foreach ($Event in $EventsToDisplay) {
                            if ($Event.'SI Signing Scenario' -eq 'Kernel-Mode') {
                                $Event
                            }
                        }
                    }

                    if (($null -eq $EventsToDisplay) -and ($EventsToDisplay.Count -eq 0)) {
                        Write-ColorfulTextWDACConfig -Color HotPink -InputText 'No logs were found to display based on the current filters. Exiting...'
                        return
                    }

                    # If the ExtremeVisibility switch is used, then display all the properties of the logs without any filtering
                    if (-NOT $ExtremeVisibility) {
                        Set-LogPropertiesVisibility -LogType Evtx/Local -EventsToDisplay $EventsToDisplay
                    }

                    # Display the logs in a grid view using the build-in cmdlet
                    $SelectedLogs = $EventsToDisplay | Out-GridView -OutputMode Multiple -Title "Displaying $($EventsToDisplay.count) Code Integrity Logs of $LogType type(s)"

                    [WDACConfig.Logger]::Write("ConvertTo-WDACPolicy: Selected logs count: $($SelectedLogs.count)")

                    if (!$BasePolicyGUID -and !$BasePolicyFile -and !$PolicyToAddLogsTo) {
                        Write-ColorfulTextWDACConfig -Color HotPink -InputText 'A more specific parameter was not provided to define what to do with the selected logs. Exiting...'
                        return
                    }

                    # If the user has selected any logs, then create a WDAC policy for them, otherwise return
                    if ($null -eq $SelectedLogs) {
                        return
                    }

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Checking for kernel-protected files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    $KernelProtectedFileLogs = Test-KernelProtectedFiles -Logs $SelectedLogs

                    if ($null -ne $KernelProtectedFileLogs) {

                        [WDACConfig.Logger]::Write("ConvertTo-WDACPolicy: Kernel protected files count: $($KernelProtectedFileLogs.count)")

                        [WDACConfig.Logger]::Write('Copying the template policy to the staging area')
                        Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $WDACPolicyKernelProtectedPath -Force

                        [WDACConfig.Logger]::Write('Emptying the policy file in preparation for the new data insertion')
                        Clear-CiPolicy_Semantic -Path $WDACPolicyKernelProtectedPath

                        # Find the kernel protected files that have PFN property
                        $KernelProtectedFileLogsWithPFN = foreach ($Log in $KernelProtectedFileLogs) {
                            if ($Log.PackageFamilyName) {
                                $Log
                            }
                        }

                        New-PFNLevelRules -PackageFamilyNames $KernelProtectedFileLogsWithPFN.PackageFamilyName -XmlFilePath $WDACPolicyKernelProtectedPath

                        # Add the Kernel protected files policy to the list of policies to merge
                        $PolicyFilesToMerge.Add($WDACPolicyKernelProtectedPath)

                        [WDACConfig.Logger]::Write("ConvertTo-WDACPolicy: Kernel protected files with PFN property: $($KernelProtectedFileLogsWithPFN.count)")
                        [WDACConfig.Logger]::Write("ConvertTo-WDACPolicy: Kernel protected files without PFN property: $($KernelProtectedFileLogs.count - $KernelProtectedFileLogsWithPFN.count)")

                        # Removing the logs that were used to create PFN rules from the rest of the logs
                        $SelectedLogs = foreach ($Log in $SelectedLogs) {
                            if ($Log -notin $KernelProtectedFileLogsWithPFN) {
                                $Log
                            }
                        }
                    }

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Generating the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Copying the template policy to the staging area')
                    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $WDACPolicyPathTEMP -Force

                    [WDACConfig.Logger]::Write('Emptying the policy file in preparation for the new data insertion')
                    Clear-CiPolicy_Semantic -Path $WDACPolicyPathTEMP

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Building Signers and file rule' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Building the Signer and Hash objects from the selected logs')
                    [WDACConfig.FileBasedInfoPackage]$DataToUseForBuilding = [WDACConfig.SignerAndHashBuilder]::BuildSignerAndHashObjects((ConvertTo-HashtableArray $SelectedLogs), 'EVTX', $Level, $false)

                    if ($Null -ne $DataToUseForBuilding.FilePublisherSigners -and $DataToUseForBuilding.FilePublisherSigners.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating File Publisher Level rules')
                        New-FilePublisherLevelRules -FilePublisherSigners $DataToUseForBuilding.FilePublisherSigners -XmlFilePath $WDACPolicyPathTEMP
                    }
                    if ($Null -ne $DataToUseForBuilding.PublisherSigners -and $DataToUseForBuilding.PublisherSigners.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating Publisher Level rules')
                        New-PublisherLevelRules -PublisherSigners $DataToUseForBuilding.PublisherSigners -XmlFilePath $WDACPolicyPathTEMP
                    }
                    if ($Null -ne $DataToUseForBuilding.CompleteHashes -and $DataToUseForBuilding.CompleteHashes.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating Hash Level rules')
                        New-HashLevelRules -Hashes $DataToUseForBuilding.CompleteHashes -XmlFilePath $WDACPolicyPathTEMP
                    }

                    # MERGERS

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Performing merge operations' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Merging the Hash Level rules')
                    Remove-AllowElements_Semantic -Path $WDACPolicyPathTEMP
                    [WDACConfig.CloseEmptyXmlNodesSemantic]::Close($WDACPolicyPathTEMP)

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Making sure there are no duplicates' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Merging the Signer Level rules')
                    Remove-DuplicateFileAttrib_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    # 2 passes are necessary
                    Merge-Signers_Semantic -XmlFilePath $WDACPolicyPathTEMP
                    Merge-Signers_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    # This function runs twice, once for signed data and once for unsigned data
                    [WDACConfig.CloseEmptyXmlNodesSemantic]::Close($WDACPolicyPathTEMP)

                    $PolicyFilesToMerge.Add($WDACPolicyPathTEMP)

                    $null = Merge-CIPolicy -PolicyPaths $PolicyFilesToMerge -OutputFilePath $WDACPolicyPath

                    Switch ($True) {

                        { $null -ne $BasePolicyFile } {

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Associating the Supplemental policy with the user input base policy')

                            # Objectify the user input base policy file to extract its Base policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

                            [System.String]$SupplementalPolicyID = [WDACConfig.SetCiPolicyInfo]::Set($WDACPolicyPath, $true, $SuppPolicyName, $InputXMLObj.SiPolicy.BasePolicyID, $null)

                            # Configure policy rule options
                            [WDACConfig.CiRuleOptions]::Set($WDACPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            Copy-Item -Path $WDACPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $WDACPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip"))
                            }
                        }
                        { $null -ne $BasePolicyGUID } {

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Assigning the user input GUID to the base policy ID of the supplemental policy')

                            [System.String]$SupplementalPolicyID = [WDACConfig.SetCiPolicyInfo]::Set($WDACPolicyPath, $true, $SuppPolicyName, $BasePolicyGUID, $null)

                            # Configure policy rule options
                            [WDACConfig.CiRuleOptions]::Set($WDACPolicyPath, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            Copy-Item -Path $WDACPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $WDACPolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip"))
                            }
                        }
                        { $null -ne $PolicyToAddLogsTo } {
                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Adding the logs to the policy that user selected')

                            $MacrosBackup = Checkpoint-Macros -XmlFilePathIn $PolicyToAddLogsTo -Backup

                            # Objectify the user input policy file to extract its policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $PolicyToAddLogsTo)

                            $null = [WDACConfig.SetCiPolicyInfo]::Set($WDACPolicyPath, $true, $SuppPolicyName, $null, $null)

                            # Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
                            [WDACConfig.CiRuleOptions]::Set($WDACPolicyPath, $null, $null, $null, $null, $null, $null, $null, $null, $null, $true)

                            $null = Merge-CIPolicy -PolicyPaths $PolicyToAddLogsTo, $WDACPolicyPath -OutputFilePath $PolicyToAddLogsTo

                            [WDACConfig.UpdateHvciOptions]::Update($PolicyToAddLogsTo)

                            if ($null -ne $MacrosBackup) {
                                [WDACConfig.Logger]::Write('Restoring the Macros in the policy')
                                Checkpoint-Macros -XmlFilePathOut $PolicyToAddLogsTo -Restore -MacrosBackup $MacrosBackup
                            }

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyToAddLogsTo -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip"))
                            }
                        }
                    }

                    #Endregion Base To Supplemental Policy Association and Deployment
                }
                'MDEAdvancedHunting' {

                    # Define the policy name if it wasn't provided by the user
                    [System.String]$SuppPolicyName = $PSBoundParameters['SuppPolicyName'] ?? "Supplemental Policy from MDE Advanced Hunting - $CurrentDate"

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

                    [WDACConfig.Logger]::Write('Optimizing the MDE CSV data')
                    [System.Collections.Hashtable[]]$OptimizedCSVData = Optimize-MDECSVData -CSVPath $MDEAHLogs -StagingArea $StagingArea

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Identifying the correlated data in the MDE CSV data' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Identifying the correlated data in the MDE CSV data')

                    if (($null -eq $OptimizedCSVData) -or ($OptimizedCSVData.Count -eq 0)) {
                        Write-ColorfulTextWDACConfig -Color HotPink -InputText 'No valid MDE Advanced Hunting logs available. Exiting...'
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
                        $MDEAHLogsToDisplay = foreach ($Event in $MDEAHLogsToDisplay) {
                            if ($Event.'SiSigningScenario' -eq '0') {
                                $Event
                            }
                        }
                    }

                    if (($null -eq $MDEAHLogsToDisplay) -or ($MDEAHLogsToDisplay.Count -eq 0)) {
                        Write-ColorfulTextWDACConfig -Color HotPink -InputText 'No MDE Advanced Hunting logs available based on the selected filters. Exiting...'
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

                    [WDACConfig.Logger]::Write('Displaying the MDE Advanced Hunting logs in a GUI')
                    [PSCustomObject[]]$SelectMDEAHLogs = $MDEAHLogsToDisplay | Out-GridView -OutputMode Multiple -Title "Displaying $($MDEAHLogsToDisplay.count) Microsoft Defender for Endpoint Advanced Hunting Logs"

                    if (($null -eq $SelectMDEAHLogs) -or ($SelectMDEAHLogs.Count -eq 0)) {
                        Write-ColorfulTextWDACConfig -Color HotPink -InputText 'No MDE Advanced Hunting logs were selected to create a WDAC policy from. Exiting...'
                        return
                    }

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Preparing an empty policy to save the logs to' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Define the path where the final MDE AH XML policy file will be saved
                    [System.IO.FileInfo]$OutputPolicyPathMDEAH = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

                    [WDACConfig.Logger]::Write('Copying the template policy to the staging area')
                    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $OutputPolicyPathMDEAH -Force

                    [WDACConfig.Logger]::Write('Emptying the policy file in preparation for the new data insertion')
                    Clear-CiPolicy_Semantic -Path $OutputPolicyPathMDEAH

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Building the Signer and Hash objects from the selected MDE AH logs' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Building the Signer and Hash objects from the selected MDE AH logs')
                    [WDACConfig.FileBasedInfoPackage]$DataToUseForBuilding = [WDACConfig.SignerAndHashBuilder]::BuildSignerAndHashObjects((ConvertTo-HashtableArray $SelectMDEAHLogs), 'MDEAH', $Level, $false)

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Creating rules for different levels' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    if ($Null -ne $DataToUseForBuilding.FilePublisherSigners -and $DataToUseForBuilding.FilePublisherSigners.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating File Publisher Level rules')
                        New-FilePublisherLevelRules -FilePublisherSigners $DataToUseForBuilding.FilePublisherSigners -XmlFilePath $OutputPolicyPathMDEAH
                    }
                    if ($Null -ne $DataToUseForBuilding.PublisherSigners -and $DataToUseForBuilding.PublisherSigners.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating Publisher Level rules')
                        New-PublisherLevelRules -PublisherSigners $DataToUseForBuilding.PublisherSigners -XmlFilePath $OutputPolicyPathMDEAH
                    }
                    if ($Null -ne $DataToUseForBuilding.CompleteHashes -and $DataToUseForBuilding.CompleteHashes.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating Hash Level rules')
                        New-HashLevelRules -Hashes $DataToUseForBuilding.CompleteHashes -XmlFilePath $OutputPolicyPathMDEAH
                    }

                    # MERGERS

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Merging the Hash Level rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Merging the Hash Level rules')
                    Remove-AllowElements_Semantic -Path $OutputPolicyPathMDEAH
                    [WDACConfig.CloseEmptyXmlNodesSemantic]::Close($OutputPolicyPathMDEAH)

                    # Remove-UnreferencedFileRuleRefs -xmlFilePath $OutputPolicyPathMDEAH

                    $CurrentStep++
                    Write-Progress -Id 31 -Activity 'Merging the Signer Level rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Merging the Signer Level rules')
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
                    [WDACConfig.CloseEmptyXmlNodesSemantic]::Close($OutputPolicyPathMDEAH)

                    #Region Base To Supplemental Policy Association and Deployment
                    Switch ($True) {

                        { $null -ne $BasePolicyFile } {

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Associating the Supplemental policy with the user input base policy')

                            # Objectify the user input base policy file to extract its Base policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

                            [System.String]$SupplementalPolicyID = [WDACConfig.SetCiPolicyInfo]::Set($OutputPolicyPathMDEAH, $true, $SuppPolicyName, $InputXMLObj.SiPolicy.BasePolicyID, $null)

                            # Configure policy rule options
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathMDEAH, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            Copy-Item -Path $OutputPolicyPathMDEAH -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathMDEAH -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip"))
                            }
                        }
                        { $null -ne $BasePolicyGUID } {

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Assigning the user input GUID to the base policy ID of the supplemental policy')

                            [System.String]$SupplementalPolicyID = [WDACConfig.SetCiPolicyInfo]::Set($OutputPolicyPathMDEAH, $true, $SuppPolicyName, $BasePolicyGUID, $null)

                            # Configure policy rule options
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathMDEAH, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            Copy-Item -Path $OutputPolicyPathMDEAH -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathMDEAH -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip"))
                            }
                        }
                        { $null -ne $PolicyToAddLogsTo } {
                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Adding the logs to the policy that user selected')

                            $MacrosBackup = Checkpoint-Macros -XmlFilePathIn $PolicyToAddLogsTo -Backup

                            # Objectify the user input policy file to extract its policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $PolicyToAddLogsTo)

                            $null = [WDACConfig.SetCiPolicyInfo]::Set($OutputPolicyPathMDEAH, $true, $SuppPolicyName, $null, $null)

                            # Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathMDEAH, $null, $null, $null, $null, $null, $null, $null, $null, $null, $true)

                            $null = Merge-CIPolicy -PolicyPaths $PolicyToAddLogsTo, $OutputPolicyPathMDEAH -OutputFilePath $PolicyToAddLogsTo

                            [WDACConfig.UpdateHvciOptions]::Update($PolicyToAddLogsTo)

                            if ($null -ne $MacrosBackup) {
                                [WDACConfig.Logger]::Write('Restoring the Macros in the policy')
                                Checkpoint-Macros -XmlFilePathOut $PolicyToAddLogsTo -Restore -MacrosBackup $MacrosBackup
                            }

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyToAddLogsTo -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip"))
                            }
                        }
                        Default {
                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathMDEAH, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)
                            Copy-Item -Path $OutputPolicyPathMDEAH -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
                        }
                    }

                    #Endregion Base To Supplemental Policy Association and Deployment
                }
                'EVTXFiles' {

                    # Define the policy name if it wasn't provided by the user
                    [System.String]$SuppPolicyName = $PSBoundParameters['SuppPolicyName'] ?? "Supplemental Policy from Evtx files - $CurrentDate"

                    # The total number of the main steps for the progress bar to render
                    [System.UInt16]$TotalSteps = 6
                    [System.UInt16]$CurrentStep = 0

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Processing the selected Evtx files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    if ($null -ne $StartTime -and $StartTime -is [System.DateTime]) {
                        [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PolicyName:$FilterByPolicyNames -Date $StartTime -Type:$LogType -LogSource EVTXFiles -EVTXFilePaths $EVTXLogs
                    }
                    else {
                        [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PolicyName:$FilterByPolicyNames -Type:$LogType -LogSource EVTXFiles -EVTXFilePaths $EVTXLogs
                    }

                    [PSCustomObject[]]$EventsToDisplay = Select-LogProperties -Logs $EventsToDisplay

                    # If the KernelModeOnly switch is used, then filter the events by the 'Requested Signing Level' property
                    if ($KernelModeOnly) {
                        $EventsToDisplay = foreach ($Event in $EventsToDisplay) {
                            if ($Event.'SI Signing Scenario' -eq 'Kernel-Mode') {
                                $Event
                            }
                        }
                    }

                    if (($null -eq $EventsToDisplay) -and ($EventsToDisplay.Count -eq 0)) {
                        Write-ColorfulTextWDACConfig -Color HotPink -InputText 'No logs were found to display based on the current filters. Exiting...'
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
                    $SelectedLogs = $EventsToDisplay | Out-GridView -OutputMode Multiple -Title "Displaying $($EventsToDisplay.count) Code Integrity Logs of $LogType type(s)"

                    [WDACConfig.Logger]::Write("ConvertTo-WDACPolicy: Selected logs count: $($SelectedLogs.count)")

                    if (($null -eq $SelectedLogs) -or ( $SelectedLogs.Count -eq 0)) {
                        Write-ColorfulTextWDACConfig -Color HotPink -InputText 'No logs were selected to create a WDAC policy from. Exiting...'
                        return
                    }

                    # Define the path where the final Evtx XML policy file will be saved
                    [System.IO.FileInfo]$OutputPolicyPathEVTX = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

                    [WDACConfig.Logger]::Write('Copying the template policy to the staging area')
                    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $OutputPolicyPathEVTX -Force

                    [WDACConfig.Logger]::Write('Emptying the policy file in preparation for the new data insertion')
                    Clear-CiPolicy_Semantic -Path $OutputPolicyPathEVTX

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Building Signers and file rule' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Building the Signer and Hash objects from the selected Evtx logs')
                    [WDACConfig.FileBasedInfoPackage]$DataToUseForBuilding = [WDACConfig.SignerAndHashBuilder]::BuildSignerAndHashObjects((ConvertTo-HashtableArray $SelectedLogs), 'EVTX', $Level, $false)

                    if ($Null -ne $DataToUseForBuilding.FilePublisherSigners -and $DataToUseForBuilding.FilePublisherSigners.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating File Publisher Level rules')
                        New-FilePublisherLevelRules -FilePublisherSigners $DataToUseForBuilding.FilePublisherSigners -XmlFilePath $OutputPolicyPathEVTX
                    }
                    if ($Null -ne $DataToUseForBuilding.PublisherSigners -and $DataToUseForBuilding.PublisherSigners.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating Publisher Level rules')
                        New-PublisherLevelRules -PublisherSigners $DataToUseForBuilding.PublisherSigners -XmlFilePath $OutputPolicyPathEVTX
                    }
                    if ($Null -ne $DataToUseForBuilding.CompleteHashes -and $DataToUseForBuilding.CompleteHashes.Count -gt 0) {
                        [WDACConfig.Logger]::Write('Creating Hash Level rules')
                        New-HashLevelRules -Hashes $DataToUseForBuilding.CompleteHashes -XmlFilePath $OutputPolicyPathEVTX
                    }

                    # MERGERS

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Performing merge operations' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Merging the Hash Level rules')
                    Remove-AllowElements_Semantic -Path $OutputPolicyPathEVTX
                    [WDACConfig.CloseEmptyXmlNodesSemantic]::Close($OutputPolicyPathEVTX)

                    # Remove-UnreferencedFileRuleRefs -xmlFilePath $OutputPolicyPathEVTX

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Making sure there are no duplicates' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [WDACConfig.Logger]::Write('Merging the Signer Level rules')
                    Remove-DuplicateFileAttrib_Semantic -XmlFilePath $OutputPolicyPathEVTX

                    # 2 passes are necessary
                    Merge-Signers_Semantic -XmlFilePath $OutputPolicyPathEVTX
                    Merge-Signers_Semantic -XmlFilePath $OutputPolicyPathEVTX

                    # This function runs twice, once for signed data and once for unsigned data
                    [WDACConfig.CloseEmptyXmlNodesSemantic]::Close($OutputPolicyPathEVTX)

                    #Region Base To Supplemental Policy Association and Deployment

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Generating the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Switch ($True) {

                        { $null -ne $BasePolicyFile } {

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Associating the Supplemental policy with the user input base policy')

                            # Objectify the user input base policy file to extract its Base policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

                            [System.String]$SupplementalPolicyID = [WDACConfig.SetCiPolicyInfo]::Set($OutputPolicyPathEVTX, $true, $SuppPolicyName, $InputXMLObj.SiPolicy.BasePolicyID, $null)

                            # Configure policy rule options
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathEVTX, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            Copy-Item -Path $OutputPolicyPathEVTX -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathEVTX -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip"))
                            }
                        }
                        { $null -ne $BasePolicyGUID } {

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Assigning the user input GUID to the base policy ID of the supplemental policy')

                            [System.String]$SupplementalPolicyID = [WDACConfig.SetCiPolicyInfo]::Set($OutputPolicyPathEVTX, $true, $SuppPolicyName, $BasePolicyGUID, $null)

                            # Configure policy rule options
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathEVTX, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)

                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            Copy-Item -Path $OutputPolicyPathEVTX -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $OutputPolicyPathEVTX -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$SupplementalPolicyID.cip"))
                            }
                        }
                        { $null -ne $PolicyToAddLogsTo } {
                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Adding the logs to the policy that user selected')

                            $MacrosBackup = Checkpoint-Macros -XmlFilePathIn $PolicyToAddLogsTo -Backup

                            # Objectify the user input policy file to extract its policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $PolicyToAddLogsTo)

                            $null = [WDACConfig.SetCiPolicyInfo]::Set($OutputPolicyPathEVTX, $true, $SuppPolicyName, $null, $null)

                            # Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathEVTX, $null, $null, $null, $null, $null, $null, $null, $null, $null, $true)

                            $null = Merge-CIPolicy -PolicyPaths $PolicyToAddLogsTo, $OutputPolicyPathEVTX -OutputFilePath $PolicyToAddLogsTo

                            [WDACConfig.UpdateHvciOptions]::Update($PolicyToAddLogsTo)

                            if ($null -ne $MacrosBackup) {
                                [WDACConfig.Logger]::Write('Restoring the Macros in the policy')
                                Checkpoint-Macros -XmlFilePathOut $PolicyToAddLogsTo -Restore -MacrosBackup $MacrosBackup
                            }

                            if ($Deploy) {
                                $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyToAddLogsTo -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip")

                                [WDACConfig.CiToolHelper]::UpdatePolicy((Join-Path -Path $StagingArea -ChildPath "$($InputXMLObj.SiPolicy.PolicyID).cip"))
                            }
                        }
                        Default {
                            [WDACConfig.Logger]::Write('ConvertTo-WDACPolicy: Copying the policy file to the User Config directory')
                            [WDACConfig.CiRuleOptions]::Set($OutputPolicyPathEVTX, [WDACConfig.CiRuleOptions+PolicyTemplate]::Supplemental, $null, $null, $null, $null, $null, $null, $null, $null, $null)
                            Copy-Item -Path $OutputPolicyPathEVTX -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
                        }
                    }

                    #Endregion Base To Supplemental Policy Association and Deployment
                }
            }
        }
        catch {
            throw $_
        }
        Finally {
            Write-Progress -Id 30 -Activity 'Complete.' -Completed
            Write-Progress -Id 31 -Activity 'Complete.' -Completed
            Write-Progress -Id 32 -Activity 'Complete.' -Completed

            if (![WDACConfig.GlobalVars]::DebugPreference) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    # .EXTERNALHELP ..\Help\ConvertTo-WDACPolicy.xml
}
