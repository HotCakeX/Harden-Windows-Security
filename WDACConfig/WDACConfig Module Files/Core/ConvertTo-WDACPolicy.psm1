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

                [System.String[]]$PolicyGUIDs = foreach ($Policy in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if ($Policy.IsSystemPolicy -ne 'True') {
                        if ($Policy.PolicyID -eq $Policy.BasePolicyID) {
                            $Policy.PolicyID
                        }
                    }
                }

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

                [System.String[]]$Policies = foreach ($Policy in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if ($Policy.FriendlyName -and ($Policy.PolicyID -eq $Policy.BasePolicyID)) {
                        $Policy.FriendlyName
                    }
                }

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
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        [System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'ConvertTo-WDACPolicy: Importing the required sub-modules'
        # Defining list of generic modules required for this cmdlet to import
        [System.String[]]$ModulesToImport = @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\Shared\Receive-CodeIntegrityLogs.psm1",
            "$ModuleRootPath\Shared\New-StagingArea.psm1",
            "$ModuleRootPath\Shared\Set-LogPropertiesVisibility.psm1",
            "$ModuleRootPath\Shared\Select-LogProperties.psm1",
            "$ModuleRootPath\Shared\Test-KernelProtectedFiles.psm1"
        )
        # Add XML Ops module to the list of modules to import
        $ModulesToImport += ([WDACConfig.FileUtility]::GetFilesFast("$ModuleRootPath\XMLOps", $null, '.psm1')).FullName
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

                    [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PostProcessing OnlyExisting -PolicyName:$FilterByPolicyNames -Date:$StartTime -Type:$LogType
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
                        Write-ColorfulText -Color HotPink -InputText 'No logs were found to display based on the current filters. Exiting...'
                        return
                    }

                    # If the ExtremeVisibility switch is used, then display all the properties of the logs without any filtering
                    if (-NOT $ExtremeVisibility) {
                        Set-LogPropertiesVisibility -LogType Evtx/Local -EventsToDisplay $EventsToDisplay
                    }

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

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Checking for kernel-protected files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    $KernelProtectedFileLogs = Test-KernelProtectedFiles -Logs $SelectedLogs

                    if ($null -ne $KernelProtectedFileLogs) {

                        Write-Verbose -Message "ConvertTo-WDACPolicy: Kernel protected files count: $($KernelProtectedFileLogs.count)"

                        Write-Verbose -Message 'Copying the template policy to the staging area'
                        Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $WDACPolicyKernelProtectedPath -Force

                        Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
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

                        Write-Verbose -Message "ConvertTo-WDACPolicy: Kernel protected files with PFN property: $($KernelProtectedFileLogsWithPFN.count)"
                        Write-Verbose -Message "ConvertTo-WDACPolicy: Kernel protected files without PFN property: $($KernelProtectedFileLogs.count - $KernelProtectedFileLogsWithPFN.count)"

                        # Removing the logs that were used to create PFN rules from the rest of the logs
                        $SelectedLogs = foreach ($Log in $SelectedLogs) {
                            if ($Log -notin $KernelProtectedFileLogsWithPFN) {
                                $Log
                            }
                        }
                    }

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Generating the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Copying the template policy to the staging area'
                    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $WDACPolicyPathTEMP -Force

                    Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
                    Clear-CiPolicy_Semantic -Path $WDACPolicyPathTEMP

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Building Signers and file rule' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Building the Signer and Hash objects from the selected logs'
                    [PSCustomObject]$DataToUseForBuilding = Build-SignerAndHashObjects -Data $SelectedLogs -IncomingDataType EVTX

                    if ($Null -ne $DataToUseForBuilding.FilePublisherSigners -and $DataToUseForBuilding.FilePublisherSigners.Count -gt 0) {
                        Write-Verbose -Message 'Creating File Publisher Level rules'
                        New-FilePublisherLevelRules -FilePublisherSigners $DataToUseForBuilding.FilePublisherSigners -XmlFilePath $WDACPolicyPathTEMP
                    }
                    if ($Null -ne $DataToUseForBuilding.PublisherSigners -and $DataToUseForBuilding.PublisherSigners.Count -gt 0) {
                        Write-Verbose -Message 'Creating Publisher Level rules'
                        New-PublisherLevelRules -PublisherSigners $DataToUseForBuilding.PublisherSigners -XmlFilePath $WDACPolicyPathTEMP
                    }
                    if ($Null -ne $DataToUseForBuilding.CompleteHashes -and $DataToUseForBuilding.CompleteHashes.Count -gt 0) {
                        Write-Verbose -Message 'Creating Hash Level rules'
                        New-HashLevelRules -Hashes $DataToUseForBuilding.CompleteHashes -XmlFilePath $WDACPolicyPathTEMP
                    }

                    # MERGERS

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Performing merge operations' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Merging the Hash Level rules'
                    Remove-AllowElements_Semantic -Path $WDACPolicyPathTEMP
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    $CurrentStep++
                    Write-Progress -Id 30 -Activity 'Making sure there are no duplicates' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Merging the Signer Level rules'
                    Remove-DuplicateFileAttrib_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    # 2 passes are necessary
                    Merge-Signers_Semantic -XmlFilePath $WDACPolicyPathTEMP
                    Merge-Signers_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    # This function runs twice, once for signed data and once for unsigned data
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    $PolicyFilesToMerge.Add($WDACPolicyPathTEMP)

                    Merge-CIPolicy -PolicyPaths $PolicyFilesToMerge -OutputFilePath $WDACPolicyPath | Out-Null

                    Switch ($True) {

                        { $null -ne $BasePolicyFile } {

                            Write-Verbose -Message 'ConvertTo-WDACPolicy: Associating the Supplemental policy with the user input base policy'

                            # Objectify the user input base policy file to extract its Base policy ID
                            $InputXMLObj = [System.Xml.XmlDocument](Get-Content -Path $BasePolicyFile)

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName $SuppPolicyName -SupplementsBasePolicyID $InputXMLObj.SiPolicy.BasePolicyID -ResetPolicyID
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

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName $SuppPolicyName -SupplementsBasePolicyID $BasePolicyGUID -ResetPolicyID
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

                            Set-CIPolicyIdInfo -FilePath $WDACPolicyPath -PolicyName $SuppPolicyName -ResetPolicyID | Out-Null

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
                        $MDEAHLogsToDisplay = foreach ($Event in $MDEAHLogsToDisplay) {
                            if ($Event.'SiSigningScenario' -eq '0') {
                                $Event
                            }
                        }
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
                    [System.IO.FileInfo]$OutputPolicyPathMDEAH = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

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

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathMDEAH -PolicyName $SuppPolicyName -SupplementsBasePolicyID $InputXMLObj.SiPolicy.BasePolicyID -ResetPolicyID
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

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathMDEAH -PolicyName $SuppPolicyName -SupplementsBasePolicyID $BasePolicyGUID -ResetPolicyID
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

                            Set-CIPolicyIdInfo -FilePath $OutputPolicyPathMDEAH -PolicyName $SuppPolicyName -ResetPolicyID | Out-Null

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

                    # Define the policy name if it wasn't provided by the user
                    [System.String]$SuppPolicyName = $PSBoundParameters['SuppPolicyName'] ?? "Supplemental Policy from Evtx files - $CurrentDate"

                    # The total number of the main steps for the progress bar to render
                    [System.UInt16]$TotalSteps = 6
                    [System.UInt16]$CurrentStep = 0

                    $CurrentStep++
                    Write-Progress -Id 32 -Activity 'Processing the selected Evtx files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    [PSCustomObject[]]$EventsToDisplay = Receive-CodeIntegrityLogs -PolicyName:$FilterByPolicyNames -Date:$StartTime -Type:$LogType -LogSource EVTXFiles -EVTXFilePaths $EVTXLogs
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
                    [System.IO.FileInfo]$OutputPolicyPathEVTX = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

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

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathEVTX -PolicyName $SuppPolicyName -SupplementsBasePolicyID $InputXMLObj.SiPolicy.BasePolicyID -ResetPolicyID
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

                            [System.String]$SupplementalPolicyID = Set-CIPolicyIdInfo -FilePath $OutputPolicyPathEVTX -PolicyName $SuppPolicyName -SupplementsBasePolicyID $BasePolicyGUID -ResetPolicyID
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

                            Set-CIPolicyIdInfo -FilePath $OutputPolicyPathEVTX -PolicyName $SuppPolicyName -ResetPolicyID | Out-Null

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
.PARAMETER SuppPolicyName
    The name of the supplemental policy to create. If not specified, the cmdlet will generate a proper name based on the selected source and time.
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

Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'PolicyToAddLogsTo' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)
Register-ArgumentCompleter -CommandName 'ConvertTo-WDACPolicy' -ParameterName 'BasePolicyFile' -ScriptBlock ([WDACConfig.ArgumentCompleters]::ArgumentCompleterXmlFilePathsPicker)

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDAT0vp+1WV/7nM
# +14CtGIIgRnVxxo6ml0IR7wEydJsSKCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgbcECvCvIhqOmQcSw+McJa7Fikor+6skSIZ8GcNKxqTswDQYJKoZIhvcNAQEB
# BQAEggIAjJcfKUFwTAS9C0TamDcuNmz9ctxo6zdlzA7jQSwVIj/jYUdb84lL7vXs
# d78lfS3NNdmaaplB2TnMvUmtUKtmTwDFrPG2i7T4LGWIpfIxen7SdcOWdZ+JhZMv
# F7QixzT0HaIRF5uMTrnPCwIKrKVABtFD7EaoQkXjhCblS2Hxu59TktAvd/G2/h67
# EtJpOvS2+l+Ky1Z4JedlXNIpG7LYZK+DQcF6FAhdmS3k6HOCJzC0ANmyBYaLo6R4
# KWbz+QhbvsTceiHzFgFFAYmlZXbeaDmJACxmv0Ivou/dX+QCa914NVc5A6pHrlbB
# g/XTYPGzHHZYdRNqf58pOk239qwnkStCnE+3IJLG+fJ6Y4xg8ORWBWP7Ad212NKU
# zXBjNq/Z5/MX4rpVZD0umnzsoBM1uDeQK0MrQPPNeJE5wYus0qbeW+ovL4a62GDz
# lPrUAIVjPCf3Qp8YWEgbTpfrJ2eEj/z+lirPZqLjUydeJoE4yI7BSeptaYsbBtjx
# iGRv8VfKTaTFnfxahx21j4ZTlGrYuCEqI8TYGG/fARaMLT62By8q9Oj7nSCTVB/R
# j0Bt6xyi2pJ3Op2v2QbQJr7oo8bkOX2EAjRmNFnZO73a3TMwHLx5lrUHIIxFGLfe
# 2spoL4DsifJdKOjkJ+NuwuszDC+jPCdP5vvKPzh8n0UC7oSj0Xs=
# SIG # End signature block
