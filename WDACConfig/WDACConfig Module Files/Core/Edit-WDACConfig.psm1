Function Edit-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'AllowNewApps',
        PositionalBinding = $false
    )]
    [OutputType([System.String])]
    Param(
        [Alias('A')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')][System.Management.Automation.SwitchParameter]$AllowNewApps,
        [Alias('M')]
        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies')][System.Management.Automation.SwitchParameter]$MergeSupplementalPolicies,
        [Alias('U')]
        [Parameter(Mandatory = $false, ParameterSetName = 'UpdateBasePolicy')][System.Management.Automation.SwitchParameter]$UpdateBasePolicy,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [Parameter(Mandatory = $true, ParameterSetName = 'AllowNewApps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $true, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')][System.Management.Automation.SwitchParameter]$BoostedSecurity,

        [ValidateScript({
                # Validate the Policy file to make sure the user isn't accidentally trying to
                # Edit a Signed policy using Edit-WDACConfig cmdlet which is only made for Unsigned policies
                [System.Xml.XmlDocument]$XmlTest = Get-Content -Path $_
                [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                [System.String]$RedFlag3 = $XmlTest.SiPolicy.PolicyID

                # Get the currently deployed policy IDs
                Try {
                    [System.Guid[]]$CurrentPolicyIDs = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).policyID | ForEach-Object -Process { "{$_}" }
                }
                catch {
                    Throw 'No policy is deployed on the system.'
                }

                if (!$RedFlag1 -and !$RedFlag2) {
                    # Ensure the selected base policy xml file is deployed
                    if ($CurrentPolicyIDs -contains $RedFlag3) {

                        # Ensure the selected base policy xml file is valid
                        if ( Test-CiPolicy -XmlFile $_ ) {
                            return $True
                        }
                    }
                    else {
                        throw 'The currently selected policy xml file is not deployed.'
                    }
                }
                # This throw is shown only when User added a Signed policy xml file for Unsigned policy file path property in user configuration file
                # Without this, the error shown would be vague: The variable cannot be validated because the value System.String[] is not a valid value for the PolicyPath variable.
                else {
                    throw 'The policy xml file in User Configurations for UnsignedPolicyPath is a Signed policy.'
                }
            }, ErrorMessage = 'The selected policy xml file is Signed. Please use Edit-SignedWDACConfig cmdlet to edit Signed policies.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$PolicyPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies')]
        [System.Management.Automation.SwitchParameter]$KeepOldSupplementalPolicies,

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String]$SpecificFileNameLevel,

        [ValidateRange(1024KB, 18014398509481983KB)]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.UInt64]$LogSize,

        [ValidateSet([BasePolicyNamez])]
        [Parameter(Mandatory = $true, ParameterSetName = 'UpdateBasePolicy')][System.String[]]$CurrentBasePolicyName,

        [ValidateSet('DefaultWindows', 'AllowMicrosoft', 'SignedAndReputable')]
        [Parameter(Mandatory = $true, ParameterSetName = 'UpdateBasePolicy')][System.String]$NewBasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = 'UpdateBasePolicy')][System.Management.Automation.SwitchParameter]$RequireEVSigners,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        $ModulesToImport = @(
            "$ModuleRootPath\Shared\Update-Self.psm1",
            "$ModuleRootPath\Shared\Write-ColorfulText.psm1",
            "$ModuleRootPath\Shared\Set-LogSize.psm1",
            "$ModuleRootPath\Shared\Test-FilePath.psm1",
            "$ModuleRootPath\Shared\Receive-CodeIntegrityLogs.psm1",
            "$ModuleRootPath\Shared\New-SnapBackGuarantee.psm1",
            "$ModuleRootPath\Shared\New-StagingArea.psm1",
            "$ModuleRootPath\Shared\Set-LogPropertiesVisibility.psm1",
            "$ModuleRootPath\Shared\Select-LogProperties.psm1",
            "$ModuleRootPath\Shared\Test-KernelProtectedFiles.psm1",
            "$ModuleRootPath\Shared\Show-DirectoryPathPicker.psm1",
            "$ModuleRootPath\Shared\Edit-GUIDs.psm1"
        )
        $ModulesToImport += (Get-ChildItem -File -Filter '*.psm1' -LiteralPath "$ModuleRootPath\XMLOps").FullName
        Import-Module -FullyQualifiedName $ModulesToImport -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'Edit-WDACConfig'

        #Region User-Configurations-Processing-Validation
        # make sure the ParameterSet being used has PolicyPath parameter - Then enforces "mandatory" attribute for the parameter
        if ($PSCmdlet.ParameterSetName -in 'AllowNewApps', 'MergeSupplementalPolicies') {
            # If PolicyPath was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
            if (!$PolicyPath) {
                if (Test-Path -Path (Get-CommonWDACConfig -UnsignedPolicyPath)) {
                    $PolicyPath = Get-CommonWDACConfig -UnsignedPolicyPath
                }
                else {
                    throw 'PolicyPath parameter cannot be empty and no valid user configuration was found for UnsignedPolicyPath.'
                }
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # Validate the Level and Fallbacks parameters when using the Boosted Security mode
        if ($BoostedSecurity) {
            $AllowedLevelsForBoostedSecurityMode = [System.Collections.Generic.HashSet[System.String]]@('Hash', 'FileName', 'SignedVersion', 'FilePublisher', 'WHQLFilePublisher')

            if (-NOT ($AllowedLevelsForBoostedSecurityMode.Contains($Level))) {
                Throw 'When using the Boosted Security mode, the Level parameter can only contain the following values: Hash, FileName, SignedVersion, FilePublisher, WHQLFilePublisher'
            }

            foreach ($Fallback in $Fallbacks) {
                if (-NOT ($AllowedLevelsForBoostedSecurityMode.Contains($Fallback))) {
                    Throw 'When using the Boosted Security mode, the Fallbacks parameter can only contain the following values: Hash, FileName, SignedVersion, FilePublisher, WHQLFilePublisher'
                }
            }
        }
    }

    process {

        try {

            if ($AllowNewApps) {
                Set-LogSize -LogSize:$LogSize

                # Get the current date so that instead of the entire event viewer logs, only audit logs created after running this module will be captured
                Write-Verbose -Message 'Getting the current date'
                [System.DateTime]$Date = Get-Date

                # A concurrent hashtable that holds the Policy XML files in its values - This array will eventually be used to create the final Supplemental policy
                $PolicyXMLFilesArray = [System.Collections.Concurrent.ConcurrentDictionary[System.String, System.IO.FileInfo]]::new()

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 8
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Creating the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Creating a copy of the original policy in the Staging Area so that the original one will be unaffected'

                Copy-Item -Path $PolicyPath -Destination $StagingArea -Force
                [System.IO.FileInfo]$PolicyPath = Join-Path -Path $StagingArea -ChildPath (Split-Path -Path $PolicyPath -Leaf)

                Write-Verbose -Message 'Retrieving the Base policy name and ID'
                [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyPath
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).Value.String

                Write-Verbose -Message 'Creating Audit Mode CIP'
                [System.IO.FileInfo]$AuditModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'AuditMode.cip'
                Set-CiRuleOptions -FilePath $PolicyPath -RulesToAdd 'Enabled:Audit Mode'
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $AuditModeCIPPath | Out-Null

                Write-Verbose -Message 'Creating Enforced Mode CIP'
                [System.IO.FileInfo]$EnforcedModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'EnforcedMode.cip'
                Set-CiRuleOptions -FilePath $PolicyPath -RulesToRemove 'Enabled:Audit Mode'
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $EnforcedModeCIPPath | Out-Null

                #Region Snap-Back-Guarantee
                Write-Verbose -Message 'Creating Enforced Mode SnapBack guarantee'
                New-SnapBackGuarantee -Path $EnforcedModeCIPPath

                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Deploying the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Audit mode CIP'
                &'C:\Windows\System32\CiTool.exe' --update-policy $AuditModeCIPPath -json | Out-Null

                Write-Verbose -Message 'The Base policy with the following details has been Re-Deployed in Audit Mode:'
                Write-Verbose -Message "PolicyName = $PolicyName"
                Write-Verbose -Message "PolicyGUID = $PolicyID"
                #Endregion Snap-Back-Guarantee

                # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode
                Try {
                    #Region User-Interaction
                    $CurrentStep++
                    Write-Progress -Id 10 -Activity 'Waiting for user input' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-ColorfulText -Color Pink -InputText 'Audit mode deployed, start installing/running your programs now'
                    Write-ColorfulText -Color HotPink -InputText 'When you are finished, Press Enter, you will have the option to select directories to scan'
                    Pause
                    Write-ColorfulText -Color Lavender -InputText 'Select directories to scan'
                    $ProgramsPaths = Show-DirectoryPathPicker | Select-Object -Unique
                    #Endregion User-Interaction
                }
                catch {
                    Throw $_
                }
                finally {
                    $CurrentStep++
                    Write-Progress -Id 10 -Activity 'Redeploying the Base policy in Enforced Mode' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Debug -Message 'Finally Block Running'
                    &'C:\Windows\System32\CiTool.exe' --update-policy $EnforcedModeCIPPath -json | Out-Null

                    Write-Verbose -Message 'The Base policy with the following details has been Re-Deployed in Enforced Mode:'
                    Write-Verbose -Message "PolicyName = $PolicyName"
                    Write-Verbose -Message "PolicyGUID = $PolicyID"

                    Write-Verbose -Message 'Removing the SnapBack guarantee because the base policy has been successfully re-enforced'

                    Unregister-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Confirm:$false
                    Remove-Item -Path (Join-Path -Path $UserConfigDir -ChildPath 'EnforcedModeSnapBack.cmd') -Force
                }

                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Processing Audit event logs and directories' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Path for the final Supplemental policy XML
                [System.IO.FileInfo]$SuppPolicyPath = Join-Path -Path $StagingArea -ChildPath "Supplemental Policy - $SuppPolicyName.xml"
                # Path for the kernel protected files policy XML
                [System.IO.FileInfo]$KernelProtectedPolicyPath = Join-Path -Path $StagingArea -ChildPath "Kernel Protected Files - $SuppPolicyName.xml"
                # Path for the temp policy file generated from the audits logs captured during the audit phase
                [System.IO.FileInfo]$WDACPolicyPathTEMP = Join-Path -Path $StagingArea -ChildPath "TEMP policy for Audits logs - $SuppPolicyName.xml"

                # Flag indicating user has selected directory path(s)
                [System.Boolean]$HasFolderPaths = $false
                # Flag indicating audit event logs have been detected during the audit phase
                [System.Boolean]$HasAuditLogs = $false
                # Flag indicating files have been found in audit event logs during the audit phase that are not inside of any of the user-selected directory paths
                [System.Boolean]$HasExtraFiles = $false
                # Flag indicating whether the user has selected any logs from the audit logs GUI displayed to them
                [System.Boolean]$HasSelectedLogs = $false

                if ($ProgramsPaths) {
                    Write-Verbose -Message 'Here are the paths you selected:'
                    if ($Verbose) {
                        $ProgramsPaths | ForEach-Object -Process { $_.FullName }
                    }

                    $HasFolderPaths = $true

                    # Start Async job for detecting ECC-Signed files among the user-selected directories
                    [System.Management.Automation.Job2]$ECCSignedDirectoriesJob = Start-ThreadJob -ScriptBlock {
                        Param ($PolicyXMLFilesArray, $ParentVerbosePreference, $ParentDebugPreference, $ModuleRootPath, $FindWDACCompliantFiles)

                        $global:VerbosePreference = $ParentVerbosePreference
                        $global:DebugPreference = $ParentDebugPreference
                        $global:ErrorActionPreference = 'Stop'

                        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

                        Import-Module -Force -FullyQualifiedName "$ModuleRootPath\Shared\Test-ECCSignedFiles.psm1"
                        [System.IO.FileInfo]$ECCSignedFilesTempPolicyUserDirs = Join-Path -Path $using:StagingArea -ChildPath 'ECCSignedFilesTempPolicyUserDirs.xml'
                        $ECCSignedFilesTempPolicy = Test-ECCSignedFiles -Directory $using:ProgramsPaths -Process -ECCSignedFilesTempPolicy $ECCSignedFilesTempPolicyUserDirs

                        if ($ECCSignedFilesTempPolicy -as [System.IO.FileInfo]) {
                            [System.Void]$PolicyXMLFilesArray.TryAdd('Hash Rules For ECC Signed Files in User selected directories', $ECCSignedFilesTempPolicy)
                        }
                    } -StreamingHost $Host -ArgumentList $PolicyXMLFilesArray, $VerbosePreference, $DebugPreference, $ModuleRootPath, $FindWDACCompliantFiles

                    [System.Management.Automation.Job2]$DirectoryScanJob = Start-ThreadJob -InitializationScript {
                        # pre-load the ConfigCI module
                        if (Test-Path -LiteralPath 'C:\Program Files\Windows Defender\Offline' -PathType Container) {
                            [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
                            New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
                            Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
                        }
                    } -ScriptBlock {
                        Param ($ProgramsPaths, $StagingArea, $PolicyXMLFilesArray, $ParentVerbosePreference, $ParentDebugPreference)

                        $VerbosePreference = $ParentVerbosePreference

                        Write-Verbose -Message 'Scanning each of the folder paths that user selected'

                        for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                            [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                                FilePath               = "$StagingArea\ProgramDir_ScanResults$($i).xml"
                                ScanPath               = $ProgramsPaths[$i]
                                Level                  = $using:Level
                                Fallback               = $using:Fallbacks
                                MultiplePolicyFormat   = $true
                                UserWriteablePaths     = $true
                                AllowFileNameFallbacks = $true
                            }
                            # Assess user input parameters and add the required parameters to the hash table
                            if ($using:SpecificFileNameLevel) { $UserInputProgramFoldersPolicyMakerHashTable['SpecificFileNameLevel'] = $using:SpecificFileNameLevel }
                            if ($using:NoScript) { $UserInputProgramFoldersPolicyMakerHashTable['NoScript'] = $true }
                            if (!$using:NoUserPEs) { $UserInputProgramFoldersPolicyMakerHashTable['UserPEs'] = $true }

                            Write-Verbose -Message "Currently scanning: $($ProgramsPaths[$i])"
                            New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable

                            [System.Void]$PolicyXMLFilesArray.TryAdd("$($ProgramsPaths[$i]) Scan Results", "$StagingArea\ProgramDir_ScanResults$($i).xml")
                        }

                        if ($ParentDebugPreference -eq 'Continue') {
                            Write-Output -InputObject 'The directories were scanned with the following configuration'
                            Write-Output -InputObject $($UserInputProgramFoldersPolicyMakerHashTable | Format-Table)
                        }
                    } -StreamingHost $Host -ArgumentList $ProgramsPaths, $StagingArea, $PolicyXMLFilesArray, $VerbosePreference, $DebugPreference
                }
                else {
                    Write-Verbose -Message 'No directory path was selected.'
                }

                [System.Collections.Hashtable[]]$AuditEventLogsProcessingResults = Receive-CodeIntegrityLogs -Date $Date

                if (($null -ne $AuditEventLogsProcessingResults) -and ($AuditEventLogsProcessingResults.count -ne 0)) {
                    $HasAuditLogs = $true
                }
                else {
                    Write-Verbose -Message 'No audit log events were generated during the audit period.'
                }

                if ($HasAuditLogs -and $HasFolderPaths) {
                    $OutsideFiles = [System.Collections.Generic.HashSet[System.String]]@(Test-FilePath -FilePath $AuditEventLogsProcessingResults.'File Name' -DirectoryPath $ProgramsPaths)
                }

                if (($null -ne $OutsideFiles) -and ($OutsideFiles.count -ne 0)) {
                    Write-Verbose -Message "$($OutsideFiles.count) file(s) have been found in event viewer logs that don't exist in any of the folder paths you selected."
                    $HasExtraFiles = $true
                }

                # If user selected directory paths and there were files outside of those paths in the audit logs
                if ($HasExtraFiles) {

                    # Get only the log of the files that were found in event viewer logs but are not in any user selected directories
                    [PSCustomObject[]]$LogsToShow = $AuditEventLogsProcessingResults | Where-Object -FilterScript {
                        $OutsideFiles.Contains($_.'File Name')
                    }

                    [PSCustomObject[]]$LogsToShow = Select-LogProperties -Logs $LogsToShow
                    Set-LogPropertiesVisibility -LogType Evtx/Local -EventsToDisplay $LogsToShow

                    Write-ColorfulText -Color Pink -InputText 'Displaying files detected outside of any directories you selected'

                    $SelectedLogs = $LogsToShow | Out-GridView -OutputMode Multiple -Title "Displaying $($LogsToShow.count) Audit Code Integrity and AppLocker Logs"
                }
                # If user did not select any directory paths but there were files found during the audit phase in the audit event logs
                elseif (!$HasFolderPaths -and $HasAuditLogs) {
                    [PSCustomObject[]]$LogsToShow = Select-LogProperties -Logs $AuditEventLogsProcessingResults
                    Set-LogPropertiesVisibility -LogType Evtx/Local -EventsToDisplay $LogsToShow

                    Write-ColorfulText -Color Pink -InputText 'Displaying files detected outside of any directories you selected'

                    $SelectedLogs = $LogsToShow | Out-GridView -OutputMode Multiple -Title "Displaying $($LogsToShow.count) Audit Code Integrity Logs"
                }

                # if user selected any logs
                if (($null -ne $SelectedLogs) -and ($SelectedLogs.count -gt 0)) {

                    $HasSelectedLogs = $true

                    # Start Async job for detecting ECC-Signed files among the user-selected audit logs
                    [System.Management.Automation.Job2]$ECCSignedAuditLogsJob = Start-ThreadJob -ScriptBlock {
                        Param ($PolicyXMLFilesArray, $ParentVerbosePreference, $ParentDebugPreference, $ModuleRootPath, $FindWDACCompliantFiles)

                        $global:VerbosePreference = $ParentVerbosePreference
                        $global:DebugPreference = $ParentDebugPreference
                        $global:ErrorActionPreference = 'Stop'

                        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

                        Import-Module -Force -FullyQualifiedName "$ModuleRootPath\Shared\Test-ECCSignedFiles.psm1"
                        [System.IO.FileInfo]$ECCSignedFilesTempPolicyAuditLogs = Join-Path -Path $using:StagingArea -ChildPath 'ECCSignedFilesTempPolicyAuditLogs.xml'
                        $ECCSignedFilesTempPolicy = Test-ECCSignedFiles -File $($using:SelectedLogs).'Full Path' -Process -ECCSignedFilesTempPolicy $ECCSignedFilesTempPolicyAuditLogs

                        if ($ECCSignedFilesTempPolicy -as [System.IO.FileInfo]) {
                            [System.Void]$PolicyXMLFilesArray.TryAdd('Hash Rules For ECC Signed Files in User selected Audit Logs', $ECCSignedFilesTempPolicy)
                        }
                    } -StreamingHost $Host -ArgumentList $PolicyXMLFilesArray, $VerbosePreference, $DebugPreference, $ModuleRootPath, $FindWDACCompliantFiles

                    $KernelProtectedFileLogs = Test-KernelProtectedFiles -Logs $SelectedLogs

                    if ($null -ne $KernelProtectedFileLogs) {

                        Write-Verbose -Message "Kernel protected files count: $($KernelProtectedFileLogs.count)"

                        Write-Verbose -Message 'Copying the template policy to the staging area'
                        Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $KernelProtectedPolicyPath -Force

                        Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
                        Clear-CiPolicy_Semantic -Path $KernelProtectedPolicyPath

                        # Find the kernel protected files that have PFN property
                        $KernelProtectedFileLogsWithPFN = $KernelProtectedFileLogs | Where-Object -FilterScript { $_.PackageFamilyName }

                        New-PFNLevelRules -PackageFamilyNames $KernelProtectedFileLogsWithPFN.PackageFamilyName -XmlFilePath $KernelProtectedPolicyPath

                        # Add the Kernel protected files policy to the list of policies to merge
                        [System.Void]$PolicyXMLFilesArray.TryAdd('Kernel Protected files policy', $KernelProtectedPolicyPath)

                        Write-Verbose -Message "Kernel protected files with PFN property: $($KernelProtectedFileLogsWithPFN.count)"
                        Write-Verbose -Message "Kernel protected files without PFN property: $($KernelProtectedFileLogs.count - $KernelProtectedFileLogsWithPFN.count)"

                        # Removing the logs that were used to create PFN rules, from the rest of the logs
                        $SelectedLogs = $SelectedLogs | Where-Object -FilterScript { $_ -notin $KernelProtectedFileLogsWithPFN }
                    }

                    Write-Verbose -Message 'Copying the template policy to the staging area'
                    Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $WDACPolicyPathTEMP -Force

                    Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
                    Clear-CiPolicy_Semantic -Path $WDACPolicyPathTEMP

                    Write-Verbose -Message 'Building the Signer and Hash objects from the selected logs'
                    [PSCustomObject]$DataToUseForBuilding = Build-SignerAndHashObjects -Data $SelectedLogs -IncomingDataType EVTX -PubLisherToHash:$BoostedSecurity

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
                    Write-Verbose -Message 'Merging the Hash Level rules'
                    Remove-AllowElements_Semantic -Path $WDACPolicyPathTEMP
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    Write-Verbose -Message 'Merging the Signer Level rules'
                    Remove-DuplicateFileAttrib_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    # 2 passes are necessary
                    Merge-Signers_Semantic -XmlFilePath $WDACPolicyPathTEMP
                    Merge-Signers_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    # This function runs twice, once for signed data and once for unsigned data
                    Close-EmptyXmlNodes_Semantic -XmlFilePath $WDACPolicyPathTEMP

                    # Add the policy XML file to the array that holds policy XML files
                    [System.Void]$PolicyXMLFilesArray.TryAdd('Temp WDAC Policy', $WDACPolicyPathTEMP)
                }

                #Region Async-Jobs-Management

                if ($HasFolderPaths) {
                    Wait-Job -Job $DirectoryScanJob | Out-Null
                    # Redirecting Verbose and Debug output streams because they are automatically displayed already on the console using StreamingHost parameter
                    Receive-Job -Job $DirectoryScanJob 4>$null 5>$null
                    Remove-Job -Job $DirectoryScanJob -Force

                    Wait-Job -Job $ECCSignedDirectoriesJob | Out-Null
                    # Redirecting Verbose and Debug output streams because they are automatically displayed already on the console using StreamingHost parameter
                    Receive-Job -Job $ECCSignedDirectoriesJob 4>$null 5>$null
                    Remove-Job -Job $ECCSignedDirectoriesJob -Force
                }

                if ($HasSelectedLogs) {
                    Wait-Job -Job $ECCSignedAuditLogsJob | Out-Null
                    # Redirecting Verbose and Debug output streams because they are automatically displayed already on the console using StreamingHost parameter
                    Receive-Job -Job $ECCSignedAuditLogsJob 4>$null 5>$null
                    Remove-Job -Job $ECCSignedAuditLogsJob -Force
                }

                #Endregion Async-Jobs-Management

                # If none of the previous actions resulted in any policy XML files, exit the function
                if ($PolicyXMLFilesArray.Values.Count -eq 0) {
                    Write-Verbose -Message 'No directory path or audit logs were selected to create a supplemental policy. Exiting...' -Verbose
                    Return
                }

                Write-Verbose -Message 'The following policy xml files are going to be merged into the final Supplemental policy and be deployed on the system:'
                $PolicyXMLFilesArray.Values | ForEach-Object -Process { Write-Verbose -Message "$_" }

                # Merge all of the policy XML files in the array into the final Supplemental policy
                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray.Values -OutputFilePath $SuppPolicyPath | Out-Null

                #Region Supplemental-policy-processing-and-deployment

                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Creating supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Supplemental policy processing and deployment'

                Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
                [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)

                Set-CiRuleOptions -FilePath $SuppPolicyPath -Template Supplemental

                Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version '1.0.0.0'

                # Define the path for the final Supplemental policy CIP
                [System.IO.FileInfo]$SupplementalCIPPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip"

                #Region Boosted Security - Sandboxing
                # The AppIDs association must happen at the end right before converting the policy to binary because merge-cipolicy and other ConfigCI cmdlets remove the Macros
                if ($BoostedSecurity) {
                    [System.Collections.Hashtable]$InputObject = @{}
                    $InputObject['SelectedDirectoryPaths'] = $ProgramsPaths
                    $InputObject['SelectedAuditLogs'] = $AuditEventLogsProcessingResults
                    New-Macros -XmlFilePath $SuppPolicyPath -InputObject $InputObject
                }
                #Endregion Boosted Security - Sandboxing

                Write-Verbose -Message 'Convert the Supplemental policy to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $SuppPolicyPath -BinaryFilePath $SupplementalCIPPath | Out-Null

                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy $SupplementalCIPPath -json | Out-Null

                #Endregion Supplemental-policy-processing-and-deployment

                # Copy the Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $SuppPolicyPath -Destination $UserConfigDir -Force

                &$WriteFinalOutput $SuppPolicyPath
            }

            if ($MergeSupplementalPolicies) {

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 5
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Verifying the input files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                #Region Input-policy-verification
                Write-Verbose -Message 'Verifying the input policy files'
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                    Write-Verbose -Message "Getting policy ID and type of: $SuppPolicyPath"
                    [System.Xml.XmlDocument]$Supplementalxml = Get-Content -Path $SuppPolicyPath
                    [System.String]$SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID
                    [System.String]$SupplementalPolicyType = $Supplementalxml.SiPolicy.PolicyType

                    Write-Verbose -Message 'Getting the IDs of the currently deployed policies on the system'
                    [System.String[]]$DeployedPoliciesIDs = (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies.PolicyID | ForEach-Object -Process { return "{$_}" }

                    # Check the type of the user selected Supplemental policy XML files to make sure they are indeed Supplemental policies
                    Write-Verbose -Message 'Checking the type of the policy'
                    if ($SupplementalPolicyType -ne 'Supplemental Policy') {
                        Throw "The Selected XML file with GUID $SupplementalPolicyID isn't a Supplemental Policy."
                    }

                    # Check to make sure the user selected Supplemental policy XML files are deployed on the system
                    Write-Verbose -Message 'Checking the deployment status of the policy'
                    if ($DeployedPoliciesIDs -notcontains $SupplementalPolicyID) {
                        Throw "The Selected Supplemental XML file with GUID $SupplementalPolicyID isn't deployed on the system."
                    }
                }
                #Endregion Input-policy-verification

                Write-Verbose -Message 'Backing up any possible Macros in the Supplemental policies'
                $MacrosBackup = Checkpoint-Macros -XmlFilePathIn $SuppPolicyPaths -Backup

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [System.IO.FileInfo]$FinalSupplementalPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

                Write-Verbose -Message 'Merging the Supplemental policies into a single policy file'
                Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath $FinalSupplementalPath | Out-Null

                # Remove the deployed Supplemental policies that user selected from the system, because we're going to deploy the new merged policy that contains all of them
                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Removing old policies from the system' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Removing the deployed Supplemental policies that user selected from the system'
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                    # Get the policy ID of the currently selected Supplemental policy
                    [System.Xml.XmlDocument]$Supplementalxml = Get-Content -Path $SuppPolicyPath
                    [System.String]$SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID

                    Write-Verbose -Message "Removing policy with ID: $SupplementalPolicyID"
                    &'C:\Windows\System32\CiTool.exe' --remove-policy $SupplementalPolicyID -json | Out-Null
                }

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Configuring the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Preparing the final merged Supplemental policy for deployment'
                Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
                [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -ResetPolicyID -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
                [System.String]$SuppPolicyID = $SuppPolicyID.Substring(11)

                Write-Verbose -Message 'Setting HVCI to Strict'
                Set-HVCIOptions -Strict -FilePath $FinalSupplementalPath

                if ($null -ne $MacrosBackup) {
                    Write-Verbose -Message 'Restoring the Macros in the Supplemental policies'
                    Checkpoint-Macros -XmlFilePathOut $FinalSupplementalPath -Restore -MacrosBackup $MacrosBackup
                }

                Write-Verbose -Message 'Converting the Supplemental policy to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip") | Out-Null

                $CurrentStep++
                Write-Progress -Id 11 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy (Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip") -json | Out-Null

                Write-ColorfulText -Color TeaGreen -InputText "The Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones."

                # Copying the final Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $FinalSupplementalPath -Destination $UserConfigDir -Force

                # remove the old policy files at the end after ensuring the operation was successful
                if (!$KeepOldSupplementalPolicies) {
                    Write-Verbose -Message 'Removing the old policy files'
                    Remove-Item -Path $SuppPolicyPaths -Force
                }
            }

            if ($UpdateBasePolicy) {

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 5
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Getting the block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Getting the Use Mode Block Rules'
                New-WDACConfig -GetUserModeBlockRules -Deploy

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Determining the policy type' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [System.IO.FileInfo]$BasePolicyPath = Join-Path -Path $StagingArea -ChildPath 'BasePolicy.xml'

                Write-Verbose -Message 'Determining the type of the new base policy'

                [System.String]$Name = $null

                switch ($NewBasePolicyType) {
                    'AllowMicrosoft' {
                        $Name = 'AllowMicrosoft'

                        Write-Verbose -Message "The new base policy type is $Name"

                        Write-Verbose -Message 'Copying the AllowMicrosoft.xml template policy file to the Staging Area'
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $BasePolicyPath -Force

                        Write-Verbose -Message 'Setting the policy name'
                        Set-CIPolicyIdInfo -FilePath $BasePolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')"

                        Set-CiRuleOptions -FilePath $BasePolicyPath -Template Base -RequireEVSigners:$RequireEVSigners
                    }
                    'SignedAndReputable' {
                        $Name = 'SignedAndReputable'

                        Write-Verbose -Message "The new base policy type is $Name"

                        Write-Verbose -Message 'Copying the AllowMicrosoft.xml template policy file to the Staging Area'
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $BasePolicyPath -Force

                        Write-Verbose -Message 'Setting the policy name'
                        Set-CIPolicyIdInfo -FilePath $BasePolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')"

                        Set-CiRuleOptions -FilePath $BasePolicyPath -Template BaseISG -RequireEVSigners:$RequireEVSigners

                        Write-Verbose -Message 'Configuring required services for ISG authorization'
                        Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -NoNewWindow
                        Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -NoNewWindow
                    }
                    'DefaultWindows' {
                        $Name = 'DefaultWindows'

                        Write-Verbose -Message "The new base policy type is $Name"

                        Write-Verbose -Message 'Copying the DefaultWindows.xml template policy file to the Staging Area'
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination $BasePolicyPath -Force

                        if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                            Write-Verbose -Message 'Scanning the PowerShell core directory '

                            Write-ColorfulText -Color HotPink -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'

                            New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                            Write-Verbose -Message 'Merging the DefaultWindows.xml and AllowPowerShell.xml into a single policy file'
                            Merge-CIPolicy -PolicyPaths $BasePolicyPath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml') -OutputFilePath $BasePolicyPath | Out-Null
                        }

                        Write-Verbose -Message 'Setting the policy name'
                        Set-CIPolicyIdInfo -FilePath $BasePolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')"

                        Set-CiRuleOptions -FilePath $BasePolicyPath -Template Base -RequireEVSigners:$RequireEVSigners
                    }
                }

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Configuring the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Getting the policy ID of the currently deployed base policy based on the policy name that user selected'
                # In case there are multiple policies with the same name, the first one will be used
                [System.Object]$CurrentlyDeployedPolicy = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.Version = &$CalculateCIPolicyVersion $_.Version) -and ($_.Friendlyname -eq $CurrentBasePolicyName) }) | Select-Object -First 1

                [System.String]$CurrentID = $CurrentlyDeployedPolicy.BasePolicyID
                [System.Version]$CurrentVersion = $CurrentlyDeployedPolicy.Version

                # Increment the version and use it to deploy the updated policy
                [System.Version]$VersionToDeploy = &$IncrementVersion -Version $CurrentVersion

                Write-Verbose -Message "This is the current ID of deployed base policy that is going to be used in the new base policy: $CurrentID"

                Write-Verbose -Message 'Setting the policy ID and Base policy ID to the current base policy ID in the generated XML file'
                Edit-GUIDs -PolicyIDInput $CurrentID -PolicyFilePathInput $BasePolicyPath

                Write-Verbose -Message "Setting the policy version to '$VersionToDeploy' - Previous version was '$CurrentVersion'"
                Set-CIPolicyVersion -FilePath $BasePolicyPath -Version $VersionToDeploy

                Write-Verbose -Message 'Converting the base policy to a CIP file'
                [System.IO.FileInfo]$CIPPath = ConvertFrom-CIPolicy -XmlFilePath $BasePolicyPath -BinaryFilePath (Join-Path -Path $StagingArea -ChildPath "$CurrentID.cip")

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Deploying the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the new base policy with the same GUID on the system'
                &'C:\Windows\System32\CiTool.exe' --update-policy $CIPPath -json | Out-Null

                $CurrentStep++
                Write-Progress -Id 12 -Activity 'Cleaning up' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Keep the new base policy XML file that was just deployed for user to keep it
                # Defining a hashtable that contains the policy names and their corresponding XML file names + paths
                [System.Collections.Hashtable]$PolicyFiles = @{
                    'AllowMicrosoft'     = (Join-Path -Path $UserConfigDir -ChildPath 'AllowMicrosoft.xml')
                    'SignedAndReputable' = (Join-Path -Path $UserConfigDir -ChildPath 'SignedAndReputable.xml')
                    'DefaultWindows'     = (Join-Path -Path $UserConfigDir -ChildPath 'DefaultWindows.xml')
                }

                Write-Verbose -Message 'Renaming the base policy XML file to match the new base policy type'
                # Copy the new base policy to the user's config directory since Staging Area is a temporary location
                Move-Item -Path $BasePolicyPath -Destination $PolicyFiles[$NewBasePolicyType] -Force

                Write-ColorfulText -Color Pink -InputText "Base Policy has been successfully updated to $NewBasePolicyType"

                if (Get-CommonWDACConfig -UnsignedPolicyPath) {
                    Write-Verbose -Message 'Replacing the old unsigned policy path in User Configurations with the new one'
                    Set-CommonWDACConfig -UnsignedPolicyPath $PolicyFiles[$NewBasePolicyType] | Out-Null
                }
            }
        }
        Finally {
            10..12 | ForEach-Object -Process { Write-Progress -Id $_ -Activity 'Complete.' -Completed }
            if (!$Debug) {
                Remove-Item -Path $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    This cmdlet offers various options for managing the deployed Application Control (WDAC) policies.
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig
.PARAMETER AllowNewApps
    While an unsigned WDAC policy is already deployed on the system, rebootlessly turn on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked.
    This parameter also scans the Code Integrity and AppLocker logs during the audit mode phase to detect the audited files.
    It has the ability to detect and create rules for kernel-protected files, such as the main executables of the Xbox games.
.PARAMETER MergeSupplementalPolicies
    Merges multiple deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one.
.PARAMETER UpdateBasePolicy
    It can rebootlessly change the type of the deployed base policy.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
    It is used by the entire Cmdlet.
.PARAMETER Level
    The level that determines how the selected folder will be scanned.
    The default value for it is WHQLFilePublisher.
.PARAMETER Fallbacks
    The fallback level(s) that determine how the selected folder will be scanned.
    The default value for it is (FilePublisher, Hash).
.PARAMETER LogSize
    The log size to set for Code Integrity/Operational event logs
    The accepted values are between 1024 KB and 18014398509481983 KB
    The max range is the maximum allowed log size by Windows Event viewer
.PARAMETER SuppPolicyName
    The name of the Supplemental policy that will be created
.PARAMETER PolicyPath
    The path to the base policy XML file that will be used
.PARAMETER SuppPolicyPaths
    The path(s) to the Supplemental policy XML file(s) that will be used in the merge operation.
.PARAMETER KeepOldSupplementalPolicies
    Keep the old Supplemental policies that are going to be merged into a single policy
.PARAMETER NoScript
    If specified, scripts will not be scanned
.PARAMETER BoostedSecurity
    If specified, reinforced rules will be created that offer pseudo-sandbox capabilities
.PARAMETER NoUserPEs
    If specified, user mode binaries will not be scanned
.PARAMETER SpecificFileNameLevel
    The more specific level that determines how the selected file will be scanned.
.PARAMETER CurrentBasePolicyName
    The name of the currently deployed base policy that will be used
.PARAMETER NewBasePolicyType
    The type of the new base policy that will be used
.PARAMETER RequireEVSigners
    If specified, the EV Signers rule option will be added to the base policy
.PARAMETER Debug
    If specified, the extra files created during module operation will not be deleted
.PARAMETER Verbose
    If specified, the verbose output will be shown
.INPUTS
    System.UInt64
    System.String[]
    System.String
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\CoreExt\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Edit-WDACConfig' -ParameterName 'PolicyPath' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
Register-ArgumentCompleter -CommandName 'Edit-WDACConfig' -ParameterName 'SuppPolicyPaths' -ScriptBlock $ArgumentCompleterMultipleXmlFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCoYP8+jZT4pFcr
# erhj36wif8vQTU0KuaGkKqSModPV7aCCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQg7KeFG51r3dgd1HnHOe3mICb44kk2J3tRusZuX/XWuZowDQYJKoZIhvcNAQEB
# BQAEggIAo0qF3ui584zYco/kTMRWkAdTxi9d+65XGPmwQ+ioSANnqaMkzRydE5jD
# H3tmQttToSOsjuL7XCus+ctl6G67/W9xko6htiJOG8C+3bVOEvxmSF8+Tsz4/p87
# /IyviqALzrD3KhAV4Gk3Y5K5wwZcNStCExUPMNEAkbuNEucwiIjNzVl952c+J7Ue
# +mWb0dra7Uf4oUjplNwRp8DIw+ORAls7Fisp27BGZ1CsYBBni59BZ/FpwjX5D+5q
# W1hoJE77pU24EFLqRG1X9VsDbnqFFRMHrYKVZQA0ALXbkV5apUDurk3GwdYHcqRN
# 2Pu62VVutxZZgC/nz5Lc+B7rILaC+cPXiq4HhagB9NWrNwJR0szNBZjQs5rqZpHm
# ZBkhEOvfQn5iUs3O8epjGp2Fe7gf8cAtwru82SdVZU3ogbfVF7xxumMgvj61l+4w
# strR0JRCjBNAm74QDfP+lQe7vGVhjAef9su4Fe74b4oONdJnqxcyfeFmLUd/NliB
# LnBwuVJUM3IBUP4+hTyFYpbZsefyLXmhEOOf4KYASMi8JxhoP2NqZKcUmtYQA1BY
# sQ0VaMeFPMxqavbmbOrsE9v3FWY+IsaX7Su7/BKZCSFxR1Gnm44ULGmXoLvXEg6N
# c8BxMozL/N/3e+8xOpfL0IAjtfcHQoYPSAFEXil9NdvNO0kUZ5I=
# SIG # End signature block
