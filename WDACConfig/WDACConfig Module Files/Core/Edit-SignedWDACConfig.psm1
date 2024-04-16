Function Edit-SignedWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Allow New Apps Audit Events',
        PositionalBinding = $false
    )]
    [OutputType([System.String])]
    Param(
        [Alias('E')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')][System.Management.Automation.SwitchParameter]$AllowNewAppsAuditEvents,
        [Alias('A')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')][System.Management.Automation.SwitchParameter]$AllowNewApps,
        [Alias('M')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Merge Supplemental Policies')][System.Management.Automation.SwitchParameter]$MergeSupplementalPolicies,
        [Alias('U')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Update Base Policy')][System.Management.Automation.SwitchParameter]$UpdateBasePolicy,

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Allow New Apps Audit Events', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'Allow New Apps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'Merge Supplemental Policies', ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ValidateScript({ Test-CiPolicy -XmlFile $_ })]
        [Parameter(Mandatory = $true, ParameterSetName = 'Merge Supplemental Policies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo[]]$SuppPolicyPaths,

        [ValidateScript({
                # Validate the Policy file to make sure the user isn't accidentally trying to
                # Edit an Unsigned policy using Edit-SignedWDACConfig cmdlet which is only made for Signed policies
                [System.Xml.XmlDocument]$XmlTest = Get-Content -LiteralPath $_
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

                if ($RedFlag1 -or $RedFlag2) {
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
                    'The policy xml file in User Configurations for SignedPolicyPath is Unsigned policy.'
                }
            }, ErrorMessage = 'The selected policy xml file is Unsigned. Please use Edit-WDACConfig cmdlet to edit Unsigned policies.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Merge Supplemental Policies', ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$PolicyPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'Merge Supplemental Policies')]
        [System.Management.Automation.SwitchParameter]$KeepOldSupplementalPolicies,

        [ValidateSet([BasePolicyNamez])]
        [Parameter(Mandatory = $true, ParameterSetName = 'Update Base Policy')]
        [System.String[]]$CurrentBasePolicyName,

        [ValidateSet('AllowMicrosoft_Plus_Block_Rules', 'Lightly_Managed_system_Policy', 'DefaultWindows_WithBlockRules')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Update Base Policy')]
        [System.String]$NewBasePolicyType,

        [ValidatePattern('\.cer$')]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$CertPath,

        [ValidateSet([CertCNz])]
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        [ValidateRange(1024KB, 18014398509481983KB)][Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [System.UInt64]$LogSize,

        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')]
        [System.String]$SpecificFileNameLevel,

        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')][System.Management.Automation.SwitchParameter]$IncludeDeletedFiles,

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')]
        [System.String]$Level = 'WHQLFilePublisher',

        [ValidateSet([ScanLevelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')]
        [System.String[]]$Fallbacks = ('FilePublisher', 'Hash'),

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [System.IO.FileInfo]$SignToolPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'Update Base Policy')]
        [System.Management.Automation.SwitchParameter]$RequireEVSigners,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-Self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-SignTool.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Set-LogSize.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Test-FilePath.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Receive-CodeIntegrityLogs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-EmptyPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-RuleRefs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-FileRules.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-BlockRulesMeta.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-SnapBackGuarantee.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Edit-CiPolicyRuleOptions.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-StagingArea.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-Self -InvocationStatement $MyInvocation.Statement }

        [System.IO.DirectoryInfo]$StagingArea = New-StagingArea -CmdletName 'Edit-SignedWDACConfig'

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
            if (Test-Path -Path (Get-CommonWDACConfig -CertPath)) {
                [System.IO.FileInfo]$CertPath = Get-CommonWDACConfig -CertPath
            }
            else {
                throw 'CertPath parameter cannot be empty and no valid user configuration was found for it. Use the Build-WDACCertificate cmdlet to create one.'
            }
        }

        # If CertCN was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
        if (!$CertCN) {
            if ([CertCNz]::new().GetValidValues() -contains (Get-CommonWDACConfig -CertCN)) {
                [System.String]$CertCN = Get-CommonWDACConfig -CertCN
            }
            else {
                throw 'CertCN parameter cannot be empty and no valid user configuration was found for it.'
            }
        }

        # make sure the ParameterSet being used has PolicyPath parameter - Then enforces "mandatory" attribute for the parameter
        if ($PSCmdlet.ParameterSetName -in 'Allow New Apps Audit Events', 'Allow New Apps', 'Merge Supplemental Policies') {
            # If PolicyPath was not provided by user, check if a valid value exists in user configs, if so, use it, otherwise throw an error
            if (!$PolicyPath) {
                if (Test-Path -Path (Get-CommonWDACConfig -SignedPolicyPath)) {
                    $PolicyPath = Get-CommonWDACConfig -SignedPolicyPath
                }
                else {
                    throw 'PolicyPath parameter cannot be empty and no valid user configuration was found for SignedPolicyPath.'
                }
            }
        }
        #Endregion User-Configurations-Processing-Validation
        function Update-BasePolicyToEnforced {
            <#
            .SYNOPSIS
                A helper function used to redeploy the base policy in Enforced mode
            .INPUTS
                None. This function uses the global variables: $PolicyName, $PolicyID and $EnforcedModeCIPPath
            .OUTPUTS
                System.String
            #>
            &'C:\Windows\System32\CiTool.exe' --update-policy $EnforcedModeCIPPath -json | Out-Null
            Write-ColorfulText -Color Lavender -InputText 'The Base policy with the following details has been Re-Signed and Re-Deployed in Enforced Mode:'
            Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
            Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"
        }
    }

    process {

        Try {

            if ($AllowNewApps) {

                # An empty array that holds the Policy XML files - This array will eventually be used to create the final Supplemental policy
                [System.IO.FileInfo[]]$PolicyXMLFilesArray = @()

                #Initiate Live Audit Mode

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 6
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 14 -Activity 'Creating Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Creating a copy of the original policy in the Staging Area so that the original one will be unaffected'

                Copy-Item -LiteralPath $PolicyPath -Destination $StagingArea -Force
                [System.IO.FileInfo]$PolicyPath = Join-Path -Path $StagingArea -ChildPath (Split-Path -Path $PolicyPath -Leaf)

                Write-Verbose -Message 'Retrieving the Base policy name and ID'
                [System.Xml.XmlDocument]$Xml = Get-Content -LiteralPath $PolicyPath
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string

                Write-Verbose -Message 'Creating Audit Mode CIP'
                [System.IO.FileInfo]$AuditModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'AuditMode.cip'
                # Remove Unsigned policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
                # Add Audit mode policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 3
                # Create CIP for Audit Mode
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $AuditModeCIPPath | Out-Null

                Write-Verbose -Message 'Creating Enforced Mode CIP'
                [System.IO.FileInfo]$EnforcedModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'EnforcedMode.cip'
                # Remove Unsigned policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
                # Remove Audit mode policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete
                # Create CIP for Enforced Mode
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $EnforcedModeCIPPath | Out-Null

                # Change location so SignTool.exe will create outputs in the Staging Area
                Push-Location -LiteralPath $StagingArea

                # Sign both CIPs
                $AuditModeCIPPath, $EnforcedModeCIPPath | ForEach-Object -Process {
                    # Configure the parameter splat
                    [System.Collections.Hashtable]$ProcessParams = @{
                        'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "`"$_`""
                        'FilePath'     = $SignToolPathFinal
                        'NoNewWindow'  = $true
                        'Wait'         = $true
                        'ErrorAction'  = 'Stop'
                    } # Only show the output of SignTool if Verbose switch is used
                    if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }
                    # Sign the files with the specified cert
                    Start-Process @ProcessParams
                }

                Pop-Location

                Write-Verbose -Message 'Renaming the signed CIPs to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\AuditMode.cip.p7" -Destination $AuditModeCIPPath -Force
                Move-Item -LiteralPath "$StagingArea\EnforcedMode.cip.p7" -Destination $EnforcedModeCIPPath -Force

                #Region Snap-Back-Guarantee
                Write-Verbose -Message 'Creating Enforced Mode SnapBack guarantee'
                New-SnapBackGuarantee -Path $EnforcedModeCIPPath

                $CurrentStep++
                Write-Progress -Id 14 -Activity 'Deploying the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Deploy the Audit mode CIP
                Write-Verbose -Message 'Deploying the Audit mode CIP'
                &'C:\Windows\System32\CiTool.exe' --update-policy $AuditModeCIPPath -json | Out-Null

                Write-ColorfulText -Color Lavender -InputText 'The Base policy with the following details has been Re-Signed and Re-Deployed in Audit Mode:'
                Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
                Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"

                #Endregion Snap-Back-Guarantee

                # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode
                Try {
                    #Region User-Interaction
                    Write-ColorfulText -Color Pink -InputText 'Audit mode deployed, start installing your programs now'
                    Write-ColorfulText -Color HotPink -InputText 'When you have finished installing programs, Press Enter to start selecting program directories to scan'
                    Pause

                    # Store the program paths that user browses for in an array
                    [System.IO.DirectoryInfo[]]$ProgramsPaths = @()
                    Write-Host -Object 'Select program directories to scan' -ForegroundColor Cyan

                    $CurrentStep++
                    Write-Progress -Id 14 -Activity 'Waiting for user input' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Showing folder picker GUI to the user for folder path selection
                    do {
                        [System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null
                        [System.Windows.Forms.FolderBrowserDialog]$OBJ = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
                        $OBJ.InitialDirectory = "$env:SystemDrive"
                        $OBJ.Description = $Description
                        [System.Windows.Forms.Form]$Spawn = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }
                        [System.String]$Show = $OBJ.ShowDialog($Spawn)
                        If ($Show -eq 'OK') { $ProgramsPaths += $OBJ.SelectedPath }
                        else { break }
                    }
                    while ($true)
                    #Endregion User-Interaction

                    # Make sure User browsed for at least 1 directory otherwise exit
                    if ($ProgramsPaths.count -eq 0) {
                        # Finally block will be triggered to Re-Deploy Base policy in Enforced mode
                        Throw 'No program folder was selected, reverting the changes and quitting...'
                    }
                }
                catch {
                    # Complete the progress bar if there was an error, such as user not selecting any folders
                    Write-Progress -Id 14 -Activity 'Complete.' -Completed

                    # Show any extra info about any possible error that might've occurred
                    Throw $_
                }
                finally {
                    # Deploy Enforced mode CIP
                    Write-Verbose -Message 'Finally Block Running'
                    Update-BasePolicyToEnforced

                    Write-Verbose -Message 'Removing the SnapBack guarantee because the base policy has been successfully re-enforced'

                    Unregister-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Confirm:$false
                    Remove-Item -Path (Join-Path -Path $UserConfigDir -ChildPath 'EnforcedModeSnapBack.cmd') -Force
                }

                Write-Host -Object 'Here are the paths you selected:' -ForegroundColor Yellow
                $ProgramsPaths | ForEach-Object -Process { $_.FullName }

                $CurrentStep++
                Write-Progress -Id 14 -Activity 'Scanning user selected folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Scan each of the folder paths that user selected
                Write-Verbose -Message 'Scanning each of the folder paths that user selected'
                for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                    # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                    [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                        FilePath               = "$StagingArea\ProgramDir_ScanResults$($i).xml"
                        ScanPath               = $ProgramsPaths[$i]
                        Level                  = $Level
                        Fallback               = $Fallbacks
                        MultiplePolicyFormat   = $true
                        UserWriteablePaths     = $true
                        AllowFileNameFallbacks = $true
                    }
                    # Assess user input parameters and add the required parameters to the hash table
                    if ($SpecificFileNameLevel) { $UserInputProgramFoldersPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                    if ($NoScript) { $UserInputProgramFoldersPolicyMakerHashTable['NoScript'] = $true }
                    if (!$NoUserPEs) { $UserInputProgramFoldersPolicyMakerHashTable['UserPEs'] = $true }

                    # Create the supplemental policy via parameter splatting
                    Write-Verbose -Message "Currently scanning: $($ProgramsPaths[$i])"
                    New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable
                }

                Write-Verbose -Message 'Collecting all the policy files created by scanning user specified folders'

                foreach ($File in (Get-ChildItem -File -Path $StagingArea -Filter 'ProgramDir_ScanResults*.xml')) {
                    $PolicyXMLFilesArray += $File.FullName
                }

                Write-Verbose -Message 'The following policy xml files are going to be merged into the final Supplemental policy and be deployed on the system:'
                $PolicyXMLFilesArray | ForEach-Object -Process { Write-Verbose -Message "$_" }

                # Define the path for the final Supplemental policy XML
                [System.IO.FileInfo]$SuppPolicyPath = Join-Path -Path $StagingArea -ChildPath "SupplementalPolicy $SuppPolicyName.xml"

                # Merge all of the policy XML files in the array into the final Supplemental policy
                Write-Verbose -Message 'Merging all of the policy XML files in the array into the final Supplemental policy'
                Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath $SuppPolicyPath | Out-Null

                #Region Supplemental-policy-processing-and-deployment
                $CurrentStep++
                Write-Progress -Id 14 -Activity 'Creating Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
                [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)

                Write-Verbose -Message 'Adding signer rule to the Supplemental policy'
                Add-SignerRule -FilePath $SuppPolicyPath -CertificatePath $CertPath -Update -User -Kernel

                Edit-CiPolicyRuleOptions -Action Supplemental -XMLFile $SuppPolicyPath

                Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version '1.0.0.0'

                # Define the path for the final Supplemental policy CIP
                [System.IO.FileInfo]$SupplementalCIPPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip"

                Write-Verbose -Message 'Converting the Supplemental policy to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $SuppPolicyPath -BinaryFilePath $SupplementalCIPPath | Out-Null

                # Change location so SignTool.exe will create outputs in the Staging Area
                Push-Location -LiteralPath $StagingArea

                # Configure the parameter splat
                [System.Collections.Hashtable]$ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "$($SupplementalCIPPath.Name)"
                    'FilePath'     = $SignToolPathFinal
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                    'ErrorAction'  = 'Stop'
                } # Only show the output of SignTool if Verbose switch is used
                if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }

                Write-Verbose -Message 'Signing the Supplemental policy with the specified cert'
                Start-Process @ProcessParams

                Pop-Location

                Write-Verbose -Message 'Renaming the signed Supplemental policy file to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\$SuppPolicyID.cip.p7" -Destination $SupplementalCIPPath -Force

                $CurrentStep++
                Write-Progress -Id 14 -Activity 'Deploying Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy $SupplementalCIPPath -json | Out-Null

                Write-ColorfulText -Color Lavender -InputText 'Supplemental policy with the following details has been Signed and Deployed in Enforced Mode:'
                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyName = $SuppPolicyName"
                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $SuppPolicyID"

                #Endregion Supplemental-policy-processing-and-deployment

                # Copy the Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $SuppPolicyPath -Destination $UserConfigDir -Force

                Write-Progress -Id 14 -Activity 'Complete.' -Completed
            }

            if ($AllowNewAppsAuditEvents) {
                # Change Code Integrity event logs size
                if ($AllowNewAppsAuditEvents -and $LogSize) {
                    Write-Verbose -Message 'Changing Code Integrity event logs size'
                    Set-LogSize -LogSize $LogSize
                }

                # Get the current date so that instead of the entire event viewer logs, only audit logs created after running this module will be captured
                Write-Verbose -Message 'Getting the current date'
                [System.DateTime]$Date = Get-Date

                # An empty array that holds the Policy XML files - This array will eventually be used to create the final Supplemental policy
                [System.IO.FileInfo[]]$PolicyXMLFilesArray = @()

                #Initiate Live Audit Mode

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 8
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Creating Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Creating a copy of the original policy in the Staging Area so that the original one will be unaffected'

                Copy-Item -Path $PolicyPath -Destination $StagingArea -Force
                [System.IO.FileInfo]$PolicyPath = Join-Path -Path $StagingArea -ChildPath (Split-Path -Path $PolicyPath -Leaf)

                Write-Verbose -Message 'Retrieving the Base policy name and ID'
                [System.Xml.XmlDocument]$Xml = Get-Content -Path $PolicyPath
                [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
                [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string

                Write-Verbose -Message 'Creating Audit Mode CIP'
                [System.IO.FileInfo]$AuditModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'AuditMode.cip'
                # Remove Unsigned policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
                # Add Audit mode policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 3
                # Create CIP for Audit Mode
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $AuditModeCIPPath | Out-Null

                Write-Verbose -Message 'Creating Enforced Mode CIP'
                [System.IO.FileInfo]$EnforcedModeCIPPath = Join-Path -Path $StagingArea -ChildPath 'EnforcedMode.cip'
                # Remove Unsigned policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
                # Remove Audit mode policy rule option
                Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete
                # Create CIP for Enforced Mode
                ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $EnforcedModeCIPPath | Out-Null

                # Change location so SignTool.exe will create outputs in the Staging Area
                Push-Location -LiteralPath $StagingArea

                # Sign both CIPs
                $AuditModeCIPPath, $EnforcedModeCIPPath | ForEach-Object -Process {
                    # Configure the parameter splat
                    [System.Collections.Hashtable]$ProcessParams = @{
                        'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "`"$_`""
                        'FilePath'     = $SignToolPathFinal
                        'NoNewWindow'  = $true
                        'Wait'         = $true
                        'ErrorAction'  = 'Stop'
                    } # Only show the output of SignTool if Verbose switch is used
                    if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }
                    # Sign the files with the specified cert
                    Start-Process @ProcessParams
                }

                Pop-Location

                Write-Verbose -Message 'Renaming the signed CIPs to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\AuditMode.cip.p7" -Destination $AuditModeCIPPath -Force
                Move-Item -LiteralPath "$StagingArea\EnforcedMode.cip.p7" -Destination $EnforcedModeCIPPath -Force

                #Region Snap-Back-Guarantee
                Write-Verbose -Message 'Creating Enforced Mode SnapBack guarantee'
                New-SnapBackGuarantee -Path $EnforcedModeCIPPath

                # Deploy the Audit mode CIP
                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Deploying Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Audit mode CIP'
                &'C:\Windows\System32\CiTool.exe' --update-policy $AuditModeCIPPath -json | Out-Null

                Write-ColorfulText -Color Lavender -InputText 'The Base policy with the following details has been Re-Signed and Re-Deployed in Audit Mode:'
                Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
                Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"

                #Endregion Snap-Back-Guarantee

                # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode
                Try {
                    #Region User-Interaction
                    Write-ColorfulText -Color Pink -InputText 'Audit mode deployed, start installing your programs now'
                    Write-ColorfulText -Color HotPink -InputText 'When you have finished installing programs, Press Enter to start selecting program directories to scan'
                    Pause

                    # Store the program paths that user browses for in an array
                    [System.IO.DirectoryInfo[]]$ProgramsPaths = @()
                    Write-Host -Object 'Select program directories to scan' -ForegroundColor Cyan

                    $CurrentStep++
                    Write-Progress -Id 15 -Activity 'waiting for user input' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Showing folder picker GUI to the user for folder path selection
                    do {
                        [System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null
                        [System.Windows.Forms.FolderBrowserDialog]$OBJ = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
                        $OBJ.InitialDirectory = "$env:SystemDrive"
                        $OBJ.Description = $Description
                        [System.Windows.Forms.Form]$Spawn = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }
                        [System.String]$Show = $OBJ.ShowDialog($Spawn)
                        If ($Show -eq 'OK') { $ProgramsPaths += $OBJ.SelectedPath }
                        else { break }
                    }
                    while ($true)
                    #Endregion User-Interaction

                    # Make sure User browsed for at least 1 directory, otherwise exit
                    if ($ProgramsPaths.count -eq 0) {
                        # Finally block will be triggered to Re-Deploy Base policy in Enforced mode
                        Throw 'No program folder was selected, reverting the changes and quitting...'
                    }

                    Write-Host -Object 'Here are the paths you selected:' -ForegroundColor Yellow
                    $ProgramsPaths | ForEach-Object -Process { $_.FullName }

                    #Region EventCapturing
                    $CurrentStep++
                    Write-Progress -Id 15 -Activity 'Scanning event logs to create policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    # Extracting the array content from the function
                    $AuditEventLogsProcessingResults = Receive-CodeIntegrityLogs -Date $Date -PostProcessing 'Separate'

                    # Only create policy for files that are available on the disk (based on Event viewer logs)
                    # but weren't in user-selected program path(s), if there are any
                    if ($AuditEventLogsProcessingResults.AvailableFilesPaths) {

                        # Using the function to find out which files are not in the user-selected path(s), if any, to only scan those
                        # this prevents duplicate rule creation and double file copying
                        [System.IO.FileInfo[]]$TestFilePathResults = Test-FilePath -FilePath $AuditEventLogsProcessingResults.AvailableFilesPaths -DirectoryPath $ProgramsPaths

                        Write-Verbose -Message "$($TestFilePathResults.count) file(s) have been found in event viewer logs that don't exist in any of the folder paths you selected."

                        # Another check to make sure there were indeed files found in Event viewer logs but weren't in any of the user-selected path(s)
                        if ($TestFilePathResults) {

                            # Create a folder in Staging Area to copy the files that are not included in user-selected program path(s)
                            # but detected in Event viewer audit logs, scan that folder, and in the end delete it
                            [System.IO.DirectoryInfo]$TemporaryScanFolderForEventViewerFiles = New-Item -Path "$StagingArea\TemporaryScanFolderForEventViewerFiles" -ItemType Directory -Force

                            Write-Verbose -Message 'The following file(s) are being copied to the Staging Area for scanning because they were found in event logs but did not exist in any of the user-selected paths:'
                            $TestFilePathResults | ForEach-Object -Process {
                                Write-Verbose -Message "$_"
                                Copy-Item -Path $_ -Destination $TemporaryScanFolderForEventViewerFiles -Force -ErrorAction SilentlyContinue
                            }

                            # Create a policy XML file for available files on the disk

                            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                            [System.Collections.Hashtable]$AvailableFilesOnDiskPolicyMakerHashTable = @{
                                FilePath               = (Join-Path -Path $StagingArea -ChildPath 'RulesForFilesNotInUserSelectedPaths.xml')
                                ScanPath               = $TemporaryScanFolderForEventViewerFiles
                                Level                  = $Level -eq 'FilePath' ? 'FilePublisher' : $Level # Since FilePath will not be valid for files scanned in the Staging Area (because they weren't in any user-selected paths), using FilePublisher as level in case user chose FilePath as level
                                Fallback               = $Fallbacks -eq 'FilePath' ? 'Hash' : $Fallbacks # Since FilePath will not be valid for files scanned in the Staging Area (because they weren't in any user-selected paths), using Hash as Fallback in case user chose FilePath as Fallback
                                MultiplePolicyFormat   = $true
                                UserWriteablePaths     = $true
                                AllowFileNameFallbacks = $true
                            }
                            # Assess user input parameters and add the required parameters to the hash table
                            if ($SpecificFileNameLevel) { $AvailableFilesOnDiskPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                            if ($NoScript) { $AvailableFilesOnDiskPolicyMakerHashTable['NoScript'] = $true }
                            if (!$NoUserPEs) { $AvailableFilesOnDiskPolicyMakerHashTable['UserPEs'] = $true }

                            # Create the supplemental policy via parameter splatting
                            Write-Verbose -Message 'Creating a policy for files that are available on the disk but were not in user-selected program path(s)'
                            New-CIPolicy @AvailableFilesOnDiskPolicyMakerHashTable

                            # Add the policy XML file to the array that holds policy XML files
                            $PolicyXMLFilesArray += (Join-Path -Path $StagingArea -ChildPath 'RulesForFilesNotInUserSelectedPaths.xml')

                            # Delete the Temporary folder in the Staging Area
                            Write-Verbose -Message 'Deleting the Temporary folder in the Staging Area'
                            Remove-Item -Recurse -Path $TemporaryScanFolderForEventViewerFiles -Force
                        }
                    }

                    # Only create policy for files that are on longer available on the disk if there are any and
                    # if user chose to include deleted files in the final supplemental policy
                    if ($AuditEventLogsProcessingResults.DeletedFileHashes.Values -and $IncludeDeletedFiles) {

                        Write-Verbose -Message 'Attempting to create a policy for files that are no longer available on the disk but were detected in event viewer logs'

                        # Displaying the unique values and count. Even though the DeletedFileHashesEventsPolicy.xml will have many duplicates, the final supplemental policy that will be deployed on the system won't have any duplicates
                        # Because Merge-CiPolicy will automatically take care of removing them
                        Write-Verbose -Message "$(($AuditEventLogsProcessingResults.DeletedFileHashes.Values.'File Name' | Select-Object -Unique).count) file(s) have been found in event viewer logs that were run during Audit phase but are no longer on the disk, they are as follows:"
                        $AuditEventLogsProcessingResults.DeletedFileHashes.Values.'File Name' | Select-Object -Unique | ForEach-Object -Process {
                            Write-Verbose -Message "$_"
                        }

                        Write-Verbose -Message 'Creating FileRules and RuleRefs for files that are no longer available on the disk but were detected in event viewer logs'
                        [System.String]$FileRulesHashesResults = Get-FileRules -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes.Values
                        [System.String]$RuleRefsHashesResults = (Get-RuleRefs -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes.Values).Trim()

                        Write-Verbose -Message 'Saving the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the Staging Area for debugging purposes'
                        $FileRulesHashesResults + $RuleRefsHashesResults | Out-File -FilePath (Join-Path -Path $StagingArea -ChildPath 'FileRulesAndFileRefs.txt') -Force

                        Write-Verbose -Message 'Putting the Rules and RulesRefs in an empty policy file'
                        New-EmptyPolicy -RulesContent $FileRulesHashesResults -RuleRefsContent $RuleRefsHashesResults | Out-File -FilePath (Join-Path -Path $StagingArea -ChildPath 'DeletedFileHashesEventsPolicy.xml') -Force

                        Write-Verbose -Message 'Adding the policy file (DeletedFileHashesEventsPolicy.xml) that consists of rules from audit even logs, to the array of XML files'
                        $PolicyXMLFilesArray += (Join-Path -Path $StagingArea -ChildPath 'DeletedFileHashesEventsPolicy.xml')
                    }
                    #Endregion EventCapturing

                    #Region Process-Program-Folders-From-User-input
                    $CurrentStep++
                    Write-Progress -Id 15 -Activity 'Scanning user selected folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Scanning each of the folder paths that user selected'

                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                            FilePath               = "$StagingArea\ProgramDir_ScanResults$($i).xml"
                            ScanPath               = $ProgramsPaths[$i]
                            Level                  = $Level
                            Fallback               = $Fallbacks
                            MultiplePolicyFormat   = $true
                            UserWriteablePaths     = $true
                            AllowFileNameFallbacks = $true
                        }
                        # Assess user input parameters and add the required parameters to the hash table
                        if ($SpecificFileNameLevel) { $UserInputProgramFoldersPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                        if ($NoScript) { $UserInputProgramFoldersPolicyMakerHashTable['NoScript'] = $true }
                        if (!$NoUserPEs) { $UserInputProgramFoldersPolicyMakerHashTable['UserPEs'] = $true }

                        # Create the supplemental policy via parameter splatting
                        Write-Verbose -Message "Currently scanning: $($ProgramsPaths[$i])"
                        New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable
                    }

                    Write-Verbose -Message 'Collecting all the policy files created by scanning user specified folders'

                    foreach ($file in (Get-ChildItem -File -Path $StagingArea -Filter 'ProgramDir_ScanResults*.xml')) {
                        $PolicyXMLFilesArray += $file.FullName
                    }
                    #Endregion Process-Program-Folders-From-User-input

                    #Region Kernel-protected-files-automatic-detection-and-allow-rule-creation
                    # This part takes care of Kernel protected files such as the main executable of the games installed through Xbox app
                    # For these files, only Kernel can get their hashes, it passes them to event viewer and we take them from event viewer logs
                    # Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fail and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them

                    $CurrentStep++
                    Write-Progress -Id 15 -Activity 'Checking for Kernel protected files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                    Write-Verbose -Message 'Checking for Kernel protected files'

                    # Finding the file(s) first and storing them in an array
                    [System.String[]]$ExesWithNoHash = @()

                    # looping through each user-selected path(s)
                    foreach ($ProgramsPath in $ProgramsPaths) {

                        # Making sure the currently processing path has any .exe in it
                        [System.String[]]$AnyAvailableExes = (Get-ChildItem -File -Recurse -Path $ProgramsPath -Filter '*.exe').FullName

                        # if any .exe was found then continue testing them
                        if ($AnyAvailableExes) {
                            foreach ($Exe in $AnyAvailableExes) {
                                try {
                                    # Testing each executable to find the protected ones
                                    Get-FileHash -Path $Exe -ErrorAction Stop | Out-Null
                                }
                                # If the executable is protected, it will throw an exception and the module will continue to the next one
                                # Making sure only the right file is captured by narrowing down the error type.
                                # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
                                catch [System.UnauthorizedAccessException] {
                                    $ExesWithNoHash += $Exe
                                }
                            }
                        }
                    }

                    # Only proceed if any kernel protected file(s) were found in any of the user-selected directory path(s)
                    if ($ExesWithNoHash) {

                        Write-Verbose -Message 'The following Kernel protected files detected, creating allow rules for them:'
                        $ExesWithNoHash | ForEach-Object -Process { Write-Verbose -Message "$_" }

                        # Check if the file exits in the $ExesWithNoHash array
                        $KernelProtectedHashesBlockResults = Receive-CodeIntegrityLogs -Date $Date -PostProcessing 'OnlyExisting' | Where-Object -FilterScript { $ExesWithNoHash -contains $_.'File Name' } | Select-Object -Property FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'

                        # Only proceed further if any hashes belonging to the detected kernel protected files were found in Event viewer
                        # If none is found then skip this part, because user didn't run those files/programs when audit mode was turned on in base policy, so no hash was found in audit logs
                        if ($KernelProtectedHashesBlockResults) {

                            # Save the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt for debugging purposes
                        (Get-FileRules -HashesArray $KernelProtectedHashesBlockResults) + (Get-RuleRefs -HashesArray $KernelProtectedHashesBlockResults) | Out-File -FilePath (Join-Path -Path $StagingArea -ChildPath 'KernelProtectedFiles.txt') -Force

                            # Put the Rules and RulesRefs in an empty policy file
                            New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $KernelProtectedHashesBlockResults) -RuleRefsContent (Get-RuleRefs -HashesArray $KernelProtectedHashesBlockResults) | Out-File -FilePath (Join-Path -Path $StagingArea -ChildPath 'KernelProtectedFiles.xml') -Force

                            # adding the policy file to the array of xml files
                            $PolicyXMLFilesArray += (Join-Path -Path $StagingArea -ChildPath 'KernelProtectedFiles.xml')
                        }
                        else {
                            Write-Warning -Message "The following Kernel protected files detected, but no hash was found for them in Event viewer logs.`nThis means you didn't run those files/programs when Audit mode was turned on."
                            $ExesWithNoHash | ForEach-Object -Process { Write-Warning -Message "$_" }
                        }
                    }
                    else {
                        Write-Verbose -Message 'No Kernel protected files in the user selected paths were detected'
                    }
                    #Endregion Kernel-protected-files-automatic-detection-and-allow-rule-creation

                    Write-Verbose -Message 'The following policy xml files are going to be merged into the final Supplemental policy and be deployed on the system:'
                    $PolicyXMLFilesArray | ForEach-Object -Process { Write-Verbose -Message "$_" }

                    # Define the path for the final Supplemental policy XML
                    [System.IO.FileInfo]$SuppPolicyPath = Join-Path -Path $StagingArea -ChildPath "SupplementalPolicy $SuppPolicyName.xml"

                    # Merge all of the policy XML files in the array into the final Supplemental policy
                    Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath $SuppPolicyPath | Out-Null
                }
                # Unlike AllowNewApps parameter, AllowNewAppsAuditEvents parameter performs Event viewer scanning and kernel protected files detection
                # So the base policy enforced mode snap back can't happen any sooner than this point
                catch {
                    # Complete the progress bar if there was an error, such as user not selecting any folders
                    Write-Progress -Id 15 -Activity 'Complete.' -Completed

                    # Show any extra info about any possible error that might've occurred
                    Throw $_
                }
                finally {
                    # Deploy Enforced mode CIP
                    Write-Verbose -Message 'Finally Block Running'
                    Update-BasePolicyToEnforced

                    Write-Verbose -Message 'Removing the SnapBack guarantee because the base policy has been successfully re-enforced'

                    Unregister-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Confirm:$false
                    Remove-Item -Path (Join-Path -Path $UserConfigDir -ChildPath 'EnforcedModeSnapBack.cmd') -Force
                }

                #Region Supplemental-policy-processing-and-deployment

                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Creating supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Supplemental policy processing and deployment'

                Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
                [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)

                Write-Verbose -Message 'Adding signer rule to the Supplemental policy'
                Add-SignerRule -FilePath $SuppPolicyPath -CertificatePath $CertPath -Update -User -Kernel

                Edit-CiPolicyRuleOptions -Action Supplemental -XMLFile $SuppPolicyPath

                Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
                Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version '1.0.0.0'

                # Define the path for the final Supplemental policy CIP
                [System.IO.FileInfo]$SupplementalCIPPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip"

                Write-Verbose -Message 'Converting the Supplemental policy to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $SuppPolicyPath -BinaryFilePath $SupplementalCIPPath | Out-Null

                # Change location so SignTool.exe will create outputs in the Staging Area
                Push-Location -LiteralPath $StagingArea

                # Configure the parameter splat
                [System.Collections.Hashtable]$ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "$($SupplementalCIPPath.Name)"
                    'FilePath'     = $SignToolPathFinal
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                    'ErrorAction'  = 'Stop'
                }
                # Only show the output of SignTool if Verbose switch is used
                if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }

                Write-Verbose -Message 'Signing the Supplemental policy with the specified cert'
                Start-Process @ProcessParams

                Pop-Location

                Write-Verbose -Message 'Renaming the signed Supplemental policy file to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\$SuppPolicyID.cip.p7" -Destination $SupplementalCIPPath -Force

                $CurrentStep++
                Write-Progress -Id 15 -Activity 'Deploying Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy $SupplementalCIPPath -json | Out-Null

                Write-ColorfulText -Color Lavender -InputText 'Supplemental policy with the following details has been Signed and Deployed in Enforced Mode:'
                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyName = $SuppPolicyName"
                Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $SuppPolicyID"

                #Endregion Supplemental-policy-processing-and-deployment

                # Copy the Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $SuppPolicyPath -Destination $UserConfigDir -Force

                Write-Progress -Id 15 -Activity 'Complete.' -Completed
            }

            if ($MergeSupplementalPolicies) {
                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 5
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Verifying the input files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [System.IO.FileInfo]$FinalSupplementalPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyName.xml"

                Write-Verbose -Message 'Merging the Supplemental policies into a single policy file'
                Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath $FinalSupplementalPath | Out-Null

                # Remove the deployed Supplemental policies that user selected from the system, because we're going to deploy the new merged policy that contains all of them
                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Removing old policies from the system' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Removing the deployed Supplemental policies that user selected from the system'
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                    # Get the policy ID of the currently selected Supplemental policy
                    [System.Xml.XmlDocument]$Supplementalxml = Get-Content -Path $SuppPolicyPath
                    [System.String]$SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID

                    Write-Verbose -Message "Removing policy with ID: $SupplementalPolicyID"
                    &'C:\Windows\System32\CiTool.exe' --remove-policy $SupplementalPolicyID -json | Out-Null

                    # remove the old policy files unless user chose to keep them
                    if (!$KeepOldSupplementalPolicies) {
                        Write-Verbose -Message "Removing the old policy file: $SuppPolicyPath"
                        Remove-Item -Path $SuppPolicyPath -Force
                    }
                }

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Configuring the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Preparing the final merged Supplemental policy for deployment'
                Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
                [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $FinalSupplementalPath -ResetPolicyID -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
                [System.String]$SuppPolicyID = $SuppPolicyID.Substring(11)

                Write-Verbose -Message 'Adding signer rules to the Supplemental policy'
                Add-SignerRule -FilePath $FinalSupplementalPath -CertificatePath $CertPath -Update -User -Kernel

                Write-Verbose -Message 'Setting HVCI to Strict'
                Set-HVCIOptions -Strict -FilePath $FinalSupplementalPath

                Write-Verbose -Message 'Removing the Unsigned mode policy rule option'
                Set-RuleOption -FilePath $FinalSupplementalPath -Option 6 -Delete

                # Defining paths for the final Supplemental policy CIP
                [System.IO.FileInfo]$FinalSupplementalCIPPath = Join-Path -Path $StagingArea -ChildPath "$SuppPolicyID.cip"

                Write-Verbose -Message 'Converting the Supplemental policy to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $FinalSupplementalPath -BinaryFilePath $FinalSupplementalCIPPath | Out-Null

                # Change location so SignTool.exe will create outputs in the Staging Area
                Push-Location -LiteralPath $StagingArea

                # Configure the parameter splat
                [System.Collections.Hashtable]$ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "$($FinalSupplementalCIPPath.Name)"
                    'FilePath'     = $SignToolPathFinal
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                    'ErrorAction'  = 'Stop'
                } # Only show the output of SignTool if Verbose switch is used
                if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }

                Write-Verbose -Message 'Signing the Supplemental policy with the specified cert'
                Start-Process @ProcessParams

                Pop-Location

                Write-Verbose -Message 'Renaming the signed Supplemental policy file to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\$SuppPolicyID.cip.p7" -Destination $FinalSupplementalCIPPath -Force

                $CurrentStep++
                Write-Progress -Id 16 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the Supplemental policy'
                &'C:\Windows\System32\CiTool.exe' --update-policy $FinalSupplementalCIPPath -json | Out-Null

                Write-ColorfulText -Color TeaGreen -InputText "The Signed Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones.`nSystem Restart is not immediately needed but eventually required to finish the removal of the previous individual Supplemental policies."

                # Copying the final Supplemental policy to the user's config directory since Staging Area is a temporary location
                Copy-Item -Path $FinalSupplementalPath -Destination $UserConfigDir -Force

                Write-Progress -Id 16 -Activity 'Complete.' -Completed
            }

            if ($UpdateBasePolicy) {

                # The total number of the main steps for the progress bar to render
                [System.UInt16]$TotalSteps = 5
                [System.UInt16]$CurrentStep = 0

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Getting the block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Getting the Use-Mode Block Rules'
                [System.IO.FileInfo]$MSFTRecommendedBlockRulesPath = Get-BlockRulesMeta -SaveDirectory $StagingArea

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Determining the policy type' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                [System.IO.FileInfo]$BasePolicyPath = Join-Path -Path $StagingArea -ChildPath 'BasePolicy.xml'
                [System.IO.FileInfo]$AllowMicrosoftTemplatePath = Join-Path -Path $StagingArea -ChildPath 'AllowMicrosoft.xml'
                [System.IO.FileInfo]$DefaultWindowsTemplatePath = Join-Path -Path $StagingArea -ChildPath 'DefaultWindows_Enforced.xml'

                Write-Verbose -Message 'Determining the type of the new base policy'
                switch ($NewBasePolicyType) {

                    'AllowMicrosoft_Plus_Block_Rules' {
                        Write-Verbose -Message 'The new base policy type is AllowMicrosoft_Plus_Block_Rules'

                        Write-Verbose -Message 'Copying the AllowMicrosoft.xml template policy file to the Staging Area'
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $AllowMicrosoftTemplatePath -Force

                        Write-Verbose -Message 'Merging the AllowMicrosoft.xml and Use-Mode Block Rules into a single policy file'
                        Merge-CIPolicy -PolicyPaths $AllowMicrosoftTemplatePath, $MSFTRecommendedBlockRulesPath -OutputFilePath $BasePolicyPath | Out-Null

                        Write-Verbose -Message 'Setting the policy name'
                        Set-CIPolicyIdInfo -FilePath $BasePolicyPath -PolicyName "Allow Microsoft Plus Block Rules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"

                        Edit-CiPolicyRuleOptions -Action Base -XMLFile $BasePolicyPath
                    }

                    'Lightly_Managed_system_Policy' {
                        Write-Verbose -Message 'The new base policy type is Lightly_Managed_system_Policy'

                        Write-Verbose -Message 'Copying the AllowMicrosoft.xml template policy file to the Staging Area'
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination $AllowMicrosoftTemplatePath -Force

                        Write-Verbose -Message 'Merging the AllowMicrosoft.xml and Use-Mode Block Rules into a single policy file'
                        Merge-CIPolicy -PolicyPaths $AllowMicrosoftTemplatePath, $MSFTRecommendedBlockRulesPath -OutputFilePath $BasePolicyPath | Out-Null

                        Write-Verbose -Message 'Setting the policy name'
                        Set-CIPolicyIdInfo -FilePath $BasePolicyPath -PolicyName "Signed And Reputable policy refreshed on $(Get-Date -Format 'MM-dd-yyyy')"

                        Edit-CiPolicyRuleOptions -Action Base-ISG -XMLFile $BasePolicyPath

                        # Configure required services for ISG authorization
                        Write-Verbose -Message 'Configuring required services for ISG authorization'
                        Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -NoNewWindow
                        Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -NoNewWindow
                    }

                    'DefaultWindows_WithBlockRules' {
                        Write-Verbose -Message 'The new base policy type is DefaultWindows_WithBlockRules'

                        Write-Verbose -Message 'Copying the DefaultWindows.xml template policy file to the Staging Area'
                        Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination $DefaultWindowsTemplatePath -Force

                        # Allowing SignTool to be able to run after Default Windows base policy is deployed
                        Write-ColorfulText -Color TeaGreen -InputText 'Creating allow rules for SignTool.exe in the DefaultWindows base policy so you can continue using it after deploying the DefaultWindows base policy.'

                        Write-Verbose -Message 'Creating a new folder in the Staging Area to copy SignTool.exe to it'
                        New-Item -Path (Join-Path -Path $StagingArea -ChildPath 'TemporarySignToolFile') -ItemType Directory -Force | Out-Null

                        Write-Verbose -Message 'Copying SignTool.exe to the folder in the Staging Area'
                        Copy-Item -Path $SignToolPathFinal -Destination (Join-Path -Path $StagingArea -ChildPath 'TemporarySignToolFile') -Force

                        Write-Verbose -Message 'Scanning the folder in the Staging Area to create a policy for SignTool.exe'
                        New-CIPolicy -ScanPath (Join-Path -Path $StagingArea -ChildPath 'TemporarySignToolFile') -Level FilePublisher -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath (Join-Path -Path $StagingArea -ChildPath 'SignTool.xml')

                        if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                            Write-Verbose -Message 'Scanning the PowerShell core directory '

                            Write-ColorfulText -Color HotPink -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                            New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml')

                            Write-Verbose -Message 'Merging the DefaultWindows.xml, AllowPowerShell.xml, SignTool.xml and Use-Mode Block Rules into a single policy file'
                            Merge-CIPolicy -PolicyPaths $DefaultWindowsTemplatePath, (Join-Path -Path $StagingArea -ChildPath 'AllowPowerShell.xml'), (Join-Path -Path $StagingArea -ChildPath 'SignTool.xml'), $MSFTRecommendedBlockRulesPath -OutputFilePath $BasePolicyPath | Out-Null
                        }
                        else {
                            Write-Verbose -Message 'Not including the PowerShell core directory in the policy'
                            Write-Verbose -Message 'Merging the DefaultWindows.xml, SignTool.xml and Use-Mode Block Rules into a single policy file'
                            Merge-CIPolicy -PolicyPaths $DefaultWindowsTemplatePath, (Join-Path -Path $StagingArea -ChildPath 'SignTool.xml'), $MSFTRecommendedBlockRulesPath -OutputFilePath $BasePolicyPath | Out-Null
                        }

                        Write-Verbose -Message 'Setting the policy name'
                        Set-CIPolicyIdInfo -FilePath $BasePolicyPath -PolicyName "Default Windows Plus Block Rules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"

                        Edit-CiPolicyRuleOptions -Action Base -XMLFile $BasePolicyPath
                    }
                }

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Configuring the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                if ($UpdateBasePolicy -and $RequireEVSigners) {
                    Write-Verbose -Message 'Adding the EV Signers rule option to the base policy'
                    Set-RuleOption -FilePath $BasePolicyPath -Option 8
                }

                Write-Verbose -Message 'Getting the policy ID of the currently deployed base policy based on the policy name that user selected'
                # In case there are multiple policies with the same name, the first one will be used
                [System.String]$CurrentID = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' } | Where-Object -FilterScript { $_.Friendlyname -eq $CurrentBasePolicyName }).BasePolicyID | Select-Object -First 1
                $CurrentID = "{$CurrentID}"

                # Defining paths for the final Base policy CIP
                [System.IO.FileInfo]$BasePolicyCIPPath = Join-Path -Path $StagingArea -ChildPath "$CurrentID.cip"

                Write-Verbose -Message 'Reading the current base policy XML file'
                [System.Xml.XmlDocument]$Xml = Get-Content -Path $BasePolicyPath

                Write-Verbose -Message 'Setting the policy ID and Base policy ID to the current base policy ID in the generated XML file'
                $Xml.SiPolicy.PolicyID = $CurrentID
                $Xml.SiPolicy.BasePolicyID = $CurrentID

                Write-Verbose -Message 'Saving the updated XML file'
                $Xml.Save($BasePolicyPath)

                Write-Verbose -Message 'Adding signer rules to the base policy'
                Add-SignerRule -FilePath $BasePolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental

                Write-Verbose -Message 'Setting the policy version to 1.0.0.1'
                Set-CIPolicyVersion -FilePath $BasePolicyPath -Version '1.0.0.1'

                # Removing unsigned policy rule option
                Set-RuleOption -FilePath $BasePolicyPath -Option 6 -Delete

                Write-Verbose -Message 'Setting HVCI to Strict'
                Set-HVCIOptions -Strict -FilePath $BasePolicyPath

                Write-Verbose -Message 'Converting the base policy to a CIP file'
                ConvertFrom-CIPolicy -XmlFilePath $BasePolicyPath -BinaryFilePath $BasePolicyCIPPath | Out-Null

                # Change location so SignTool.exe will create outputs in the Staging Area
                Push-Location -LiteralPath $StagingArea

                # Configure the parameter splat
                [System.Collections.Hashtable]$ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', "$($BasePolicyCIPPath.Name)"
                    'FilePath'     = $SignToolPathFinal
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                    'ErrorAction'  = 'Stop'
                } # Only show the output of SignTool if Verbose switch is used
                if (!$Verbose) { $ProcessParams['RedirectStandardOutput'] = 'NUL' }

                Write-Verbose -Message 'Signing the base policy with the specified cert'
                Start-Process @ProcessParams

                Pop-Location

                Write-Verbose -Message 'Renaming the signed base policy file to remove the .p7 extension'
                Move-Item -LiteralPath "$StagingArea\$CurrentID.cip.p7" -Destination $BasePolicyCIPPath -Force

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Deploying the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Deploying the new base policy with the same GUID on the system'
                &'C:\Windows\System32\CiTool.exe' --update-policy $BasePolicyCIPPath -json | Out-Null

                $CurrentStep++
                Write-Progress -Id 17 -Activity 'Cleaning up' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Keep the new base policy XML file that was just deployed for user to keep it
                # Defining a hashtable that contains the policy names and their corresponding XML file names + paths
                [System.Collections.Hashtable]$PolicyFiles = @{
                    'AllowMicrosoft_Plus_Block_Rules' = (Join-Path -Path $UserConfigDir -ChildPath 'AllowMicrosoftPlusBlockRules.xml')
                    'Lightly_Managed_system_Policy'   = (Join-Path -Path $UserConfigDir -ChildPath 'SignedAndReputable.xml')
                    'DefaultWindows_WithBlockRules'   = (Join-Path -Path $UserConfigDir -ChildPath 'DefaultWindowsPlusBlockRules.xml')
                }

                Write-Verbose -Message 'Renaming the base policy XML file to match the new base policy type'
                # Copy the new base policy to the user's config directory since Staging Area is a temporary location
                Move-Item -Path $BasePolicyPath -Destination $PolicyFiles[$NewBasePolicyType] -Force

                Write-ColorfulText -Color Pink -InputText "Base Policy has been successfully updated to $NewBasePolicyType"

                if (Get-CommonWDACConfig -SignedPolicyPath) {
                    Write-Verbose -Message 'Replacing the old signed policy path in User Configurations with the new one'
                    Set-CommonWDACConfig -SignedPolicyPath $PolicyFiles[$NewBasePolicyType] | Out-Null
                }

                Write-Progress -Id 17 -Activity 'Complete.' -Completed
            }
        }
        finally {
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
.PARAMETER AllowNewAppsAuditEvents
    Rebootlessly install new apps/programs when Signed policy is already deployed, use audit events to capture installation files, scan their directories for new Supplemental policy, Sign and deploy thew Supplemental policy.
.PARAMETER AllowNewApps
    Rebootlessly install new apps/programs when Signed policy is already deployed, scan their directories for new Supplemental policy, Sign and deploy thew Supplemental policy.
.PARAMETER MergeSupplementalPolicies
    Merges multiple Signed deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one. System restart needed to take effect.
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
.EXAMPLE
    Edit-SignedWDACConfig -AllowNewAppsAuditEvents -SuppPolicyName 'New Supplemental Policy' -PolicyPath 'C:\Users\HotCakeX\Desktop\BasePolicy.xml' -CertPath 'C:\Users\HotCakeX\Desktop\MyCert.cer' -SignToolPath 'C:\signtool.exe' -Verbose
.EXAMPLE
    Edit-SignedWDACConfig -AllowNewAppsAuditEvents -SuppPolicyName 'New Supplemental Policy'
    This example creates a new Supplemental policy named 'New Supplemental Policy'. User configurations will be used to get the certificate, signed base policy and SignTool.exe paths as well as the certificate common name.
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\CoreExt\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'CertPath' -ScriptBlock $ArgumentCompleterCerFilePathsPicker
Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'PolicyPath' -ScriptBlock $ArgumentCompleterXmlFilePathsPicker
Register-ArgumentCompleter -CommandName 'Edit-SignedWDACConfig' -ParameterName 'SuppPolicyPaths' -ScriptBlock $ArgumentCompleterMultipleXmlFilePathsPicker

# SIG # Begin signature block
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDjbFXavbUf3nB4
# AVd0vtSfzEJJm2SvUDveBqvNAJEPh6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgkIcYUSR+F7OG4W2Klw/jZsfpd2H63mR5sxO/IIiFtq0wDQYJKoZIhvcNAQEB
# BQAEggIAK6Qshoq5Lco+WP4JZ8MPXsBNmBZDmO0mUhCNcd+mBI+/x7lrqrioi0By
# J/C7KBPSUEIHQTbfvpUCFNwPfb/fgIak01U/eXweDpC1nZu1YPQPYd1PIYzc4BJe
# 7BftrnF+FmbrqttEZ4XHhuEtGJ710Bi7B/T3+i8ZN4LC+VeOXp0nJ70R+CuNzz1B
# rpqa8BUa9Q11nAPm//Boy26PRxnDkEQXBIWkoP+l1cc4YoQxqq9PK1xNwtwCzCRE
# jjTBDOsiIpyUaSPE/KzkuQJOexKI0KHHa+LyO90KhQkU/Vov104bVViHl/I+Ur4q
# BUNnsrPVVl/5kWJ+usBiM0qBlMp1zz/e955ncaT87NaDEJNezKjR0vX7fgjSiXHH
# ZEBs65eH/GT0iU6roX1GF0Bvcr4B31mWqTpkOhJ/7OpfhEst7H9erJ60IRjeD/w/
# W+eRy08XCGR3VpsrI1d9i3YGLPeAnFb1wni+AABfTYCTWRTlu+yg58MUE0zZVoaK
# e1s1g7HNpymUKKAfoJd5LvEPwwfYvO+QlVX/APF7LvGO4EaxpRS9y1Fi3yewVIu/
# Rwygq/DJvqE1AvTAWL/8sN+/Yy8K3U4BjVnAq8pTfh2M1aHT3K8kZDCaLss9RR9D
# CPGYDrXi17uMatlQNkVoQyxFSVwX6x5LLXoG2oCTXKIXR3kOecE=
# SIG # End signature block
