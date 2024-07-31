Function Edit-SignedWDACConfig {
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

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFileMultiSelectPicker])]
        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $true, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')][System.Management.Automation.SwitchParameter]$BoostedSecurity,

        [ArgumentCompleter([WDACConfig.ArgCompleter.XmlFilePathsPicker])]
        [ValidateScript({
                # Validate the Policy file to make sure the user isn't accidentally trying to
                # Edit an Unsigned policy using Edit-SignedWDACConfig cmdlet which is only made for Signed policies
                [System.Xml.XmlDocument]$XmlTest = Get-Content -LiteralPath $_
                [System.String]$RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                [System.String]$RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                [System.String]$RedFlag3 = $XmlTest.SiPolicy.PolicyID

                # Get the currently deployed policy IDs and save them in a HashSet
                $CurrentPolicyIDs = [System.Collections.Generic.HashSet[System.String]]::new([System.StringComparer]::InvariantCultureIgnoreCase)
                foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies) {
                    if ($Item.IsSystemPolicy -ne 'True') {
                        [System.Void]$CurrentPolicyIDs.Add("{$($Item.policyID)}")
                    }
                }

                if ($RedFlag1 -or $RedFlag2) {
                    # Ensure the selected base policy xml file is deployed
                    if ($CurrentPolicyIDs -and $CurrentPolicyIDs.Contains($RedFlag3)) {

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
                    throw 'The currently selected policy xml file is unsigned.'
                }
            }, ErrorMessage = 'The selected policy xml file is Unsigned. Please use Edit-WDACConfig cmdlet to edit Unsigned policies.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$PolicyPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'MergeSupplementalPolicies')]
        [System.Management.Automation.SwitchParameter]$KeepOldSupplementalPolicies,

        [ArgumentCompleter({
                foreach ($Item in [WDACConfig.BasePolicyNamez]::New().GetValidValues()) {
                    if ($Item.Contains(' ')) {
                        "'$Item'"
                    }
                }
            })]
        [Parameter(Mandatory = $true, ParameterSetName = 'UpdateBasePolicy')]
        [System.String[]]$CurrentBasePolicyName,

        [ValidateSet('DefaultWindows', 'AllowMicrosoft', 'SignedAndReputable')]
        [Parameter(Mandatory = $true, ParameterSetName = 'UpdateBasePolicy')]
        [System.String]$NewBasePolicyType,

        [ArgumentCompleter([WDACConfig.ArgCompleter.SingleCerFilePicker])]
        [ValidatePattern('\.cer$')]
        [ValidateScript({ [System.IO.File]::Exists($_) }, ErrorMessage = 'The path you selected is not a file path.')]
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$CertPath,

        [ArgumentCompleter({
                foreach ($Item in [WDACConfig.CertCNz]::new().GetValidValues()) {
                    if ($Item.Contains(' ')) {
                        "'$Item'"
                    }
                }
            })]
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        [ValidateRange(1024KB, 18014398509481983KB)][Parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.UInt64]$LogSize,

        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String]$SpecificFileNameLevel,

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ArgumentCompleter({ [WDACConfig.ScanLevelz]::New().GetValidValues() })]
        [parameter(Mandatory = $false, ParameterSetName = 'AllowNewApps')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [ArgumentCompleter([WDACConfig.ArgCompleter.ExeFilePathsPicker])]
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$SignToolPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'UpdateBasePolicy')]
        [System.Management.Automation.SwitchParameter]$RequireEVSigners,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )
    Begin {
        [System.Boolean]$Verbose = $PSBoundParameters.Verbose.IsPresent ? $true : $false
        [System.Boolean]$Debug = $PSBoundParameters.Debug.IsPresent ? $true : $false
        [WDACConfig.LoggerInitializer]::Initialize($VerbosePreference, $DebugPreference, $Host)
        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -Force -FullyQualifiedName @(
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Get-SignTool.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Update-Self.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Write-ColorfulText.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Set-LogSize.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Receive-CodeIntegrityLogs.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\New-SnapBackGuarantee.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Set-LogPropertiesVisibility.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Select-LogProperties.psm1",
            "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Test-KernelProtectedFiles.psm1"
        )
        $ModulesToImport += ([WDACConfig.FileUtility]::GetFilesFast("$([WDACConfig.GlobalVars]::ModuleRootPath)\XMLOps", $null, '.psm1')).FullName
        Import-Module -FullyQualifiedName $ModulesToImport -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        if ([WDACConfig.GlobalVars]::ConfigCIBootstrap -eq $false) {
            Invoke-MockConfigCIBootstrap
            [WDACConfig.GlobalVars]::ConfigCIBootstrap = $true
        }

        [System.IO.DirectoryInfo]$StagingArea = [WDACConfig.StagingArea]::NewStagingArea('Edit-SignedWDACConfig')

        #Region User-Configurations-Processing-Validation
        # Get SignToolPath from user parameter or user config file or auto-detect it
        if ($SignToolPath) {
            [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput $SignToolPath
        } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
        else {
            [System.IO.FileInfo]$SignToolPathFinal = Get-SignTool -SignToolExePathInput (Get-CommonWDACConfig -SignToolPath)
        }

        # If CertPath parameter wasn't provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$CertPath ) {
            if ([System.IO.File]::Exists((Get-CommonWDACConfig -CertPath))) {
                [System.IO.FileInfo]$CertPath = Get-CommonWDACConfig -CertPath
            }
            else {
                throw 'CertPath parameter cannot be empty and no valid user configuration was found for it. Use the Build-WDACCertificate cmdlet to create one.'
            }
        }

        # If CertCN was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$CertCN) {
            if ([WDACConfig.CertCNz]::new().GetValidValues() -contains (Get-CommonWDACConfig -CertCN)) {
                [System.String]$CertCN = Get-CommonWDACConfig -CertCN
            }
            else {
                throw 'CertCN parameter cannot be empty and no valid user configuration was found for it.'
            }
        }
        else {
            if ([WDACConfig.CertCNz]::new().GetValidValues() -notcontains $CertCN) {
                throw "$CertCN does not belong to a subject CN of any of the deployed certificates"
            }
        }

        # make sure the ParameterSet being used has PolicyPath parameter - Then enforces "mandatory" attribute for the parameter
        if ($PSCmdlet.ParameterSetName -in 'AllowNewApps', 'MergeSupplementalPolicies') {
            # If PolicyPath was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
            if (!$PolicyPath) {
                if ([System.IO.File]::Exists((Get-CommonWDACConfig -SignedPolicyPath))) {
                    $PolicyPath = Get-CommonWDACConfig -SignedPolicyPath
                }
                else {
                    throw 'PolicyPath parameter cannot be empty and no valid user configuration was found for SignedPolicyPath.'
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

        Try {

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
                Write-Progress -Id 15 -Activity 'Creating the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Creating a copy of the original policy in the Staging Area so that the original one will be unaffected'

                Copy-Item -Path $PolicyPath -Destination $StagingArea -Force
                [System.IO.FileInfo]$PolicyPath = Join-Path -Path $StagingArea -ChildPath (Split-Path -Path $PolicyPath -Leaf)

                Write-Verbose -Message 'Retrieving the Base policy name and ID'
                [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyPath
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string

                Write-Verbose -Message 'Creating Audit Mode CIP'
                [System.IO.FileInfo]$AuditModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'AuditMode.cip'
                Set-CiRuleOptions -FilePath $PolicyPath -RulesToRemove 'Enabled:Unsigned System Integrity Policy' -RulesToAdd 'Enabled:Audit Mode'
                $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $AuditModeCIPPath

                Write-Verbose -Message 'Creating Enforced Mode CIP'
                [System.IO.FileInfo]$EnforcedModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'EnforcedMode.cip'
                Set-CiRuleOptions -FilePath $PolicyPath -RulesToRemove 'Enabled:Unsigned System Integrity Policy', 'Enabled:Audit Mode'
                $null = ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $EnforcedModeCIPPath

                # Sign both CIPs
                foreach ($CIP in ($AuditModeCIPPath, $EnforcedModeCIPPath)) {
                    [WDACConfig.CodeIntegritySigner]::InvokeCiSigning($CIP, $SignToolPathFinal, $CertCN)
                }

                Write-Verbose -Message 'Renaming the signed CIPs to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\AuditMode.cip.p7" -Destination $AuditModeCIPPath -Force
                Move-Item -LiteralPath "$StagingArea\EnforcedMode.cip.p7" -Destination $EnforcedModeCIPPath -Force

                #Region Snap-Back-Guarantee
                Write-Verbose -Message 'Creating Enforced Mode SnapBack guarantee'
                New-SnapBackGuarantee -Path $EnforcedModeCIPPath

                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Deploying the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Audit mode CIP'
                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $AuditModeCIPPath -json

                Write-Verbose -Message 'The Base policy with the following details has been Re-Signed and Re-Deployed in Audit Mode:'
                Write-Verbose -Message "PolicyName = $PolicyName"
                Write-Verbose -Message "PolicyGUID = $PolicyID"
                #Endregion Snap-Back-Guarantee

                # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode
                Try {
                    #Region User-Interaction
                    $CurrentStep++
                    Write-Progress -Id 15 -Activity 'waiting for user input' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-ColorfulText -Color Pink -InputText 'Audit mode deployed, start installing your programs now'
                    Write-ColorfulText -Color HotPink -InputText 'When you have finished installing programs, Press Enter to start selecting program directories to scan'
                    Pause
                    Write-ColorfulText -Color Lavender -InputText 'Select directories to scan'
                    [System.IO.DirectoryInfo[]]$ProgramsPaths = [WDACConfig.DirectorySelector]::SelectDirectories()
                    #Endregion User-Interaction
                }
                catch {
                    Throw $_
                }
                finally {
                    $CurrentStep++
                    Write-Progress -Id 15 -Activity 'Redeploying the Base policy in Enforced Mode' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Debug -Message 'Finally Block Running'
                    $null = &'C:\Windows\System32\CiTool.exe' --update-policy $EnforcedModeCIPPath -json

                    Write-Verbose -Message 'The Base policy with the following details has been Re-Signed and Re-Deployed in Enforced Mode:'
                    Write-Verbose -Message "PolicyName = $PolicyName"
                    Write-Verbose -Message "PolicyGUID = $PolicyID"

                    Write-Verbose -Message 'Removing the SnapBack guarantee because the base policy has been successfully re-enforced'

                    Unregister-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Confirm:$false
                    Remove-Item -Path (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'EnforcedModeSnapBack.cmd') -Force
                }

                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Processing Audit event logs and directories' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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
                        foreach ($Path in $ProgramsPaths) {
                            $Path.FullName
                        }
                    }

                    $HasFolderPaths = $true

                    # Start Async job for detecting ECC-Signed files among the user-selected directories
                    [System.Management.Automation.Job2]$ECCSignedDirectoriesJob = Start-ThreadJob -ScriptBlock {
                        Param ($PolicyXMLFilesArray, $ParentVerbosePreference, $ParentDebugPreference)

                        $global:VerbosePreference = $ParentVerbosePreference
                        $global:DebugPreference = $ParentDebugPreference
                        $global:ErrorActionPreference = 'Stop'

                        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

                        Import-Module -Force -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Test-ECCSignedFiles.psm1"
                        [System.IO.FileInfo]$ECCSignedFilesTempPolicyUserDirs = Join-Path -Path $using:StagingArea -ChildPath 'ECCSignedFilesTempPolicyUserDirs.xml'
                        $ECCSignedFilesTempPolicy = Test-ECCSignedFiles -Directory $using:ProgramsPaths -Process -ECCSignedFilesTempPolicy $ECCSignedFilesTempPolicyUserDirs

                        if ($ECCSignedFilesTempPolicy -as [System.IO.FileInfo]) {
                            [System.Void]$PolicyXMLFilesArray.TryAdd('Hash Rules For ECC Signed Files in User selected directories', $ECCSignedFilesTempPolicy)
                        }
                    } -StreamingHost $Host -ArgumentList $PolicyXMLFilesArray, $VerbosePreference, $DebugPreference

                    $DirectoryScanJob = Start-ThreadJob -InitializationScript {
                        # pre-load the ConfigCI module
                        if ([System.IO.Directory]::Exists('C:\Program Files\Windows Defender\Offline')) {
                            [System.String]$RandomGUID = [System.Guid]::NewGuid().ToString()
                            New-CIPolicy -UserPEs -ScanPath 'C:\Program Files\Windows Defender\Offline' -Level hash -FilePath ".\$RandomGUID.xml" -NoShadowCopy -PathToCatroot 'C:\Program Files\Windows Defender\Offline' -WarningAction SilentlyContinue
                            Remove-Item -LiteralPath ".\$RandomGUID.xml" -Force
                        }
                    } -ScriptBlock {
                        Param ($ProgramsPaths, $StagingArea, $PolicyXMLFilesArray, $ParentVerbosePreference, $ParentDebugPreference)

                        $VerbosePreference = $ParentVerbosePreference

                        # Write-Verbose -Message 'Scanning each of the folder paths that user selected'

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

                            #  Write-Verbose -Message "Currently scanning: $($ProgramsPaths[$i])"
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
                    $OutsideFiles = [System.Collections.Generic.HashSet[System.String]]@([WDACConfig.FileDirectoryPathComparer]::TestFilePath($ProgramsPaths, $AuditEventLogsProcessingResults.'File Name'))
                }

                if (($null -ne $OutsideFiles) -and ($OutsideFiles.count -ne 0)) {
                    Write-Verbose -Message "$($OutsideFiles.count) file(s) have been found in event viewer logs that don't exist in any of the folder paths you selected."
                    $HasExtraFiles = $true
                }

                # If user selected directory paths and there were files outside of those paths in the audit logs
                if ($HasExtraFiles) {

                    # Get only the log of the files that were found in event viewer logs but are not in any user selected directories
                    [PSCustomObject[]]$LogsToShow = foreach ($Item in $AuditEventLogsProcessingResults) {
                        if ($OutsideFiles.Contains($Item.'File Name')) {
                            $Item
                        }
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
                        Param ($PolicyXMLFilesArray, $ParentVerbosePreference, $ParentDebugPreference)

                        $global:VerbosePreference = $ParentVerbosePreference
                        $global:DebugPreference = $ParentDebugPreference
                        $global:ErrorActionPreference = 'Stop'

                        . "$([WDACConfig.GlobalVars]::ModuleRootPath)\CoreExt\PSDefaultParameterValues.ps1"

                        Import-Module -Force -FullyQualifiedName "$([WDACConfig.GlobalVars]::ModuleRootPath)\Shared\Test-ECCSignedFiles.psm1"
                        [System.IO.FileInfo]$ECCSignedFilesTempPolicyAuditLogs = Join-Path -Path $using:StagingArea -ChildPath 'ECCSignedFilesTempPolicyAuditLogs.xml'
                        $ECCSignedFilesTempPolicy = Test-ECCSignedFiles -File $($using:SelectedLogs).'Full Path' -Process -ECCSignedFilesTempPolicy $ECCSignedFilesTempPolicyAuditLogs

                        if ($ECCSignedFilesTempPolicy -as [System.IO.FileInfo]) {
                            [System.Void]$PolicyXMLFilesArray.TryAdd('Hash Rules For ECC Signed Files in User selected Audit Logs', $ECCSignedFilesTempPolicy)
                        }
                    } -StreamingHost $Host -ArgumentList $PolicyXMLFilesArray, $VerbosePreference, $DebugPreference

                    $KernelProtectedFileLogs = Test-KernelProtectedFiles -Logs $SelectedLogs

                    if ($null -ne $KernelProtectedFileLogs) {

                        Write-Verbose -Message "Kernel protected files count: $($KernelProtectedFileLogs.count)"

                        Write-Verbose -Message 'Copying the template policy to the staging area'
                        Copy-Item -LiteralPath 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml' -Destination $KernelProtectedPolicyPath -Force

                        Write-Verbose -Message 'Emptying the policy file in preparation for the new data insertion'
                        Clear-CiPolicy_Semantic -Path $KernelProtectedPolicyPath

                        # Find the kernel protected files that have PFN property
                        $KernelProtectedFileLogsWithPFN = foreach ($Item in $KernelProtectedFileLogs) {
                            if ($Item.PackageFamilyName) {
                                $Item
                            }
                        }

                        New-PFNLevelRules -PackageFamilyNames $KernelProtectedFileLogsWithPFN.PackageFamilyName -XmlFilePath $KernelProtectedPolicyPath

                        # Add the Kernel protected files policy to the list of policies to merge
                        [System.Void]$PolicyXMLFilesArray.TryAdd('Kernel Protected files policy', $KernelProtectedPolicyPath)

                        Write-Verbose -Message "Kernel protected files with PFN property: $($KernelProtectedFileLogsWithPFN.count)"
                        Write-Verbose -Message "Kernel protected files without PFN property: $($KernelProtectedFileLogs.count - $KernelProtectedFileLogsWithPFN.count)"

                        # Removing the logs that were used to create PFN rules, from the rest of the logs
                        $SelectedLogs = foreach ($Item in $SelectedLogs) {
                            if ($Item -notin $KernelProtectedFileLogsWithPFN) {
                                $Item
                            }
                        }
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
                    $null = Wait-Job -Job $DirectoryScanJob
                    # Redirecting Verbose and Debug output streams because they are automatically displayed already on the console using StreamingHost parameter
                    Receive-Job -Job $DirectoryScanJob 4>$null 5>$null
                    Remove-Job -Job $DirectoryScanJob -Force

                    $null = Wait-Job -Job $ECCSignedDirectoriesJob
                    # Redirecting Verbose and Debug output streams because they are automatically displayed already on the console using StreamingHost parameter
                    Receive-Job -Job $ECCSignedDirectoriesJob 4>$null 5>$null
                    Remove-Job -Job $ECCSignedDirectoriesJob -Force
                }

                if ($HasSelectedLogs) {
                    $null = Wait-Job -Job $ECCSignedAuditLogsJob
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
                Write-Progress -Id 15 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                $null = Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray.Values -OutputFilePath $SuppPolicyPath

                #Region Supplemental-policy-processing-and-deployment

                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Creating supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Supplemental policy processing and deployment'

                Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
                [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)

                Write-Verbose -Message 'Adding signer rule to the Supplemental policy'
                Add-SignerRule -FilePath $SuppPolicyPath -CertificatePath $CertPath -Update -User -Kernel

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

                Write-Verbose -Message 'Converting the Supplemental policy to a CIP file'
                $null = ConvertFrom-CIPolicy -XmlFilePath $SuppPolicyPath -BinaryFilePath $SupplementalCIPPath

                [WDACConfig.CodeIntegritySigner]::InvokeCiSigning($SupplementalCIPPath, $SignToolPathFinal, $CertCN)

                Write-Verbose -Message 'Renaming the signed Supplemental policy file to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\$SuppPolicyID.cip.p7" -Destination $SupplementalCIPPath -Force

                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Deploying Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $SupplementalCIPPath -json

                #Endregion Supplemental-policy-processing-and-deployment

                # Copy the Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $SuppPolicyPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force
            }

            if ($MergeSupplementalPolicies) {
                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 5
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Verifying the input files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                #Region Input-policy-verification
                Write-Verbose -Message 'Getting the IDs of the currently deployed policies on the system'
                $DeployedPoliciesIDs = [System.Collections.Generic.HashSet[System.String]]::new([System.StringComparer]::InvariantCultureIgnoreCase)

                foreach ($Item in (&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies.PolicyID) {
                    [System.Void]$DeployedPoliciesIDs.Add("{$Item}")
                }

                Write-Verbose -Message 'Verifying the input policy files'
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                    Write-Verbose -Message "Getting policy ID and type of: $SuppPolicyPath"
                    [System.Xml.XmlDocument]$Supplementalxml = Get-Content -Path $SuppPolicyPath
                    [System.String]$SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID
                    [System.String]$SupplementalPolicyType = $Supplementalxml.SiPolicy.PolicyType

                    # Check the type of the user selected Supplemental policy XML files to make sure they are indeed Supplemental policies
                    Write-Verbose -Message 'Checking the type of the policy'
                    if ($SupplementalPolicyType -ne 'Supplemental Policy') {
                        Throw "The Selected XML file with GUID $SupplementalPolicyID isn't a Supplemental Policy."
                    }

                    # Check to make sure the user selected Supplemental policy XML files are deployed on the system
                    Write-Verbose -Message 'Checking the deployment status of the policy'
                    if ($DeployedPoliciesIDs -and !$DeployedPoliciesIDs.Contains($SupplementalPolicyID)) {
                        Throw "The Selected Supplemental XML file with GUID $SupplementalPolicyID isn't deployed on the system."
                    }
                }
                #Endregion Input-policy-verification

                Write-Verbose -Message 'Backing up any possible Macros in the Supplemental policies'
                $MacrosBackup = Checkpoint-Macros -XmlFilePathIn $SuppPolicyPaths -Backup

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [System.IO.FileInfo]$FinalSupplementalPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

                Write-Verbose -Message 'Merging the Supplemental policies into a single policy file'
                $null = Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath $FinalSupplementalPath

                # Remove the deployed Supplemental policies that user selected from the system, because we're going to deploy the new merged policy that contains all of them
                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Removing old policies from the system' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Removing the deployed Supplemental policies that user selected from the system'
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                    # Get the policy ID of the currently selected Supplemental policy
                    [System.Xml.XmlDocument]$Supplementalxml = Get-Content -Path $SuppPolicyPath
                    [System.String]$SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID

                    Write-Verbose -Message "Removing policy with ID: $SupplementalPolicyID"
                    $null = &'C:\Windows\System32\CiTool.exe' --remove-policy $SupplementalPolicyID -json
                }

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Configuring the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Preparing the final merged Supplemental policy for deployment'
                Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
                [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -ResetPolicyID -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
                [System.String]$SuppPolicyID = $SuppPolicyID.Substring(11)

                Write-Verbose -Message 'Adding signer rules to the Supplemental policy'
                Add-SignerRule -FilePath $FinalSupplementalPath -CertificatePath $CertPath -Update -User -Kernel

                Set-CiRuleOptions -FilePath $FinalSupplementalPath -RulesToRemove 'Enabled:Unsigned System Integrity Policy'

                # Defining paths for the final Supplemental policy CIP
                [System.IO.FileInfo]$FinalSupplementalCIPPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip"

                if ($null -ne $MacrosBackup) {
                    Write-Verbose -Message 'Restoring the Macros in the Supplemental policies'
                    Checkpoint-Macros -XmlFilePathOut $FinalSupplementalPath -Restore -MacrosBackup $MacrosBackup
                }

                Write-Verbose -Message 'Converting the Supplemental policy to a CIP file'
                $null = ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath

                [WDACConfig.CodeIntegritySigner]::InvokeCiSigning($FinalSupplementalCIPPath, $SignToolPathFinal, $CertCN)

                Write-Verbose -Message 'Renaming the signed Supplemental policy file to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\$SuppPolicyID.cip.p7" -Destination $FinalSupplementalCIPPath -Force

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $FinalSupplementalCIPPath -json

                Write-ColorfulText -Color TeaGreen -InputText "The Signed Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones."

                # Copying the final Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $FinalSupplementalPath -Destination ([WDACConfig.GlobalVars]::UserConfigDir) -Force

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
                Write-Progress -Id 17 -Activity 'Getting the block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Getting the Use-Mode Block Rules'
                # This shouldn't deploy the policy unsigned if it is already signed - requires build 24H2 features
                New-WDACConfig -GetUserModeBlockRules -Deploy

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Determining the policy type' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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

                        # Configure required services for ISG authorization
                        Write-Verbose -Message 'Configuring required services for ISG authorization'
                        Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -NoNewWindow
                        Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -NoNewWindow
                    }
                    'DefaultWindows' {
                        $Name = 'DefaultWindows'

                        Write-Verbose -Message "The new base policy type is $Name"

                        Write-Verbose -Message 'Copying the DefaultWindows.xml template policy file to the Staging Area'
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination $BasePolicyPath -Force

                        # Allowing SignTool to be able to run after Default Windows base policy is deployed
                        Write-ColorfulText -Color TeaGreen -InputText 'Creating allow rules for SignTool.exe in the DefaultWindows base policy so you can continue using it after deploying the DefaultWindows base policy.'

                        Write-Verbose -Message 'Creating a new folder in the Staging Area to copy SignTool.exe to it'
                        $null = New-Item -Path (Join-Path -Path $StagingArea -ChildPath 'TemporarySignToolFile') -ItemType Directory -Force

                        Write-Verbose -Message 'Copying SignTool.exe to the folder in the Staging Area'
                        Copy-Item -Path $SignToolPathFinal -Destination (Join-Path -Path $StagingArea -ChildPath 'TemporarySignToolFile') -Force

                        Write-Verbose -Message 'Scanning the folder in the Staging Area to create a policy for SignTool.exe'
                        New-CIPolicy -ScanPath (Join-Path -Path $StagingArea -ChildPath 'TemporarySignToolFile') -Level FilePublisher -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath (Join-Path -Path $StagingArea -ChildPath 'SignTool.xml')

                        if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                            Write-Verbose -Message 'Scanning the PowerShell core directory '

                            Write-ColorfulText -Color HotPink -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                            New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                            Write-Verbose -Message 'Merging the DefaultWindows.xml, AllowPowerShell.xml and SignTool.xml a single policy file'
                            $null = Merge-CIPolicy -PolicyPaths $BasePolicyPath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml'), (Join-Path -Path $StagingArea -ChildPath 'SignTool.xml') -OutputFilePath $BasePolicyPath
                        }
                        else {
                            Write-Verbose -Message 'Not including the PowerShell core directory in the policy'
                            Write-Verbose -Message 'Merging the DefaultWindows.xml and SignTool.xml into a single policy file'
                            $null = Merge-CIPolicy -PolicyPaths $BasePolicyPath, (Join-Path -Path $StagingArea -ChildPath 'SignTool.xml') -OutputFilePath $BasePolicyPath
                        }

                        Write-Verbose -Message 'Setting the policy name'
                        Set-CIPolicyIdInfo -FilePath $BasePolicyPath -PolicyName "$Name - $(Get-Date -Format 'MM-dd-yyyy')"

                        Set-CiRuleOptions -FilePath $BasePolicyPath -Template Base -RequireEVSigners:$RequireEVSigners
                    }
                }

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Configuring the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Getting the policy ID of the currently deployed base policy based on the policy name that user selected'
                # In case there are multiple policies with the same name, the first one will be used
                [System.Object]$CurrentlyDeployedPolicy = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.Version = [WDACConfig.CIPolicyVersion]::Measure($_.Version)) -and ($_.Friendlyname -eq $CurrentBasePolicyName) }) | Select-Object -First 1

                [System.String]$CurrentID = $CurrentlyDeployedPolicy.BasePolicyID
                [System.Version]$CurrentVersion = $CurrentlyDeployedPolicy.Version

                # Increment the version and use it to deploy the updated policy
                [System.Version]$VersionToDeploy = [WDACConfig.VersionIncrementer]::AddVersion($CurrentVersion)

                Write-Verbose -Message 'Setting the policy ID and Base policy ID to the current base policy ID in the generated XML file'
                [WDACConfig.PolicyEditor]::EditGUIDs($CurrentID, $BasePolicyPath)

                # Defining paths for the final Base policy CIP
                [System.IO.FileInfo]$BasePolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "$CurrentID.cip"

                Write-Verbose -Message 'Adding signer rules to the base policy'
                Add-SignerRule -FilePath $BasePolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental

                Write-Verbose -Message "Setting the policy version to '$VersionToDeploy' - Previous version was '$CurrentVersion'"
                Set-CIPolicyVersion -FilePath $BasePolicyPath -Version $VersionToDeploy

                Set-CiRuleOptions -FilePath $BasePolicyPath -RulesToRemove 'Enabled:Unsigned System Integrity Policy'

                Write-Verbose -Message 'Converting the base policy to a CIP file'
                $null = ConvertFrom-CIPolicy -XmlFilePath $BasePolicyPath -BinaryFilePath $BasePolicyCIPPath

                [WDACConfig.CodeIntegritySigner]::InvokeCiSigning($BasePolicyCIPPath, $SignToolPathFinal, $CertCN)

                Write-Verbose -Message 'Renaming the signed base policy file to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\$CurrentID.cip.p7" -Destination $BasePolicyCIPPath -Force

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Deploying the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the new base policy with the same GUID on the system'
                $null = &'C:\Windows\System32\CiTool.exe' --update-policy $BasePolicyCIPPath -json

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Cleaning up' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Keep the new base policy XML file that was just deployed for user to keep it
                # Defining a hashtable that contains the policy names and their corresponding XML file names + paths
                [System.Collections.Hashtable]$PolicyFiles = @{
                    'AllowMicrosoft'     = (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'AllowMicrosoft.xml')
                    'SignedAndReputable' = (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'SignedAndReputable.xml')
                    'DefaultWindows'     = (Join-Path -Path ([WDACConfig.GlobalVars]::UserConfigDir) -ChildPath 'DefaultWindows.xml')
                }

                Write-Verbose -Message 'Renaming the base policy XML file to match the new base policy type'
                # Copy the new base policy to the user's config directory since Staging Area is a temporary location
                Move-Item -Path $BasePolicyPath -Destination $PolicyFiles[$NewBasePolicyType] -Force

                Write-ColorfulText -Color Pink -InputText "Base Policy has been successfully updated to $NewBasePolicyType"

                if (Get-CommonWDACConfig -SignedPolicyPath) {
                    Write-Verbose -Message 'Replacing the old signed policy path in User Configurations with the new one'
                    $null = Set-CommonWDACConfig -SignedPolicyPath $PolicyFiles[$NewBasePolicyType]
                }
            }
        }
        catch {
            throw $_
        }
        finally {
            foreach ($ID in (15..17)) {
                Write-Progress -Id $ID -Activity 'Complete.' -Completed
            }

            if (!$Debug) {
                Remove-Item -LiteralPath $StagingArea -Recurse -Force
            }
        }
    }

    <#
.SYNOPSIS
    Edits Signed WDAC policies deployed on the system (Windows Defender Application Control)
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-SignedWDACConfig
.DESCRIPTION
    Using official Microsoft methods, Edits Signed WDAC policies deployed on the system (Windows Defender Application Control)

    All of the files the cmdlet creates and interacts with are stored in the following directory: C:\Program Files\WDACConfig\StagingArea\Edit-SignedWDACConfig
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Using official Microsoft methods, Edits Signed WDAC policies deployed on the system (Windows Defender Application Control)
.PARAMETER AllowNewApps
    Rebootlessly install new apps/programs when Signed policy is already deployed, scan their directories for new Supplemental policy, Sign and deploy thew Supplemental policy.
.PARAMETER MergeSupplementalPolicies
    Merges multiple Signed deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one.
.PARAMETER UpdateBasePolicy
    It can rebootlessly change the type of the deployed signed base policy. It can update the recommended block rules and/or change policy rule options in the deployed base policy.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
    It is used by the entire Cmdlet.
.PARAMETER LogSize
    The log size to set for Code Integrity/Operational event logs
    The accepted values are between 1024 KB and 18014398509481983 KB
    The max range is the maximum allowed log size by Windows Event viewer
.PARAMETER CertCN
    Common name of the certificate used to sign the deployed Signed WDAC policy
    It is Used by the entire Cmdlet
.PARAMETER Level
    The level that determines how the selected folder will be scanned.
    The default value for it is WHQLFilePublisher.
.PARAMETER Fallbacks
    The fallback level(s) that determine how the selected folder will be scanned.
    The default value for it is (FilePublisher, Hash).
.PARAMETER SuppPolicyName
    The name of the Supplemental policy to be created
.PARAMETER SuppPolicyPaths
    The paths of the Supplemental policies to be merged
.PARAMETER PolicyPath
    The path of the base policy
.PARAMETER KeepOldSupplementalPolicies
    Indicates whether to keep the old Supplemental policies after merging them into a single policy
.PARAMETER CurrentBasePolicyName
    The name of the currently deployed base policy
.PARAMETER NewBasePolicyType
    The type of the new base policy to be deployed
.PARAMETER CertPath
    The path of the certificate used to sign and deploy the Signed WDAC policy
.PARAMETER NoScript
    If specified, the cmdlet will not scan script files
.PARAMETER BoostedSecurity
    If specified, reinforced rules will be created that offer pseudo-sandbox capabilities
.PARAMETER NoUserPEs
    If specified, the cmdlet will not scan user-mode binaries
.PARAMETER SpecificFileNameLevel
    The more specific level that determines how the selected file will be scanned
.PARAMETER IncludeDeletedFiles
    If specified, the cmdlet will scan deleted files as well
.PARAMETER SignToolPath
    The path of the SignTool.exe file
.PARAMETER RequireEVSigners
    If specified, the cmdlet will add the EV Signers rule option to the base policy
.PARAMETER Verbose
    If specified, the cmdlet will show verbose output
.PARAMETER Debug
    If specified, the cmdlet will keep some files used during operations instead of deleting them
.INPUTS
    System.UInt64
    System.String
    System.String[]
    System.IO.FileInfo
    System.IO.FileInfo[]
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}
