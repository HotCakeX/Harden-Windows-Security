Function Edit-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Allow New Apps Audit Events',
        PositionalBinding = $false
    )]
    Param(
        [Alias('E')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')][System.Management.Automation.SwitchParameter]$AllowNewAppsAuditEvents,
        [Alias('A')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')][System.Management.Automation.SwitchParameter]$AllowNewApps,
        [Alias('M')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Merge Supplemental Policies')][System.Management.Automation.SwitchParameter]$MergeSupplementalPolicies,
        [Alias('U')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Update Base Policy')][System.Management.Automation.SwitchParameter]$UpdateBasePolicy,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = 'The Supplemental Policy Name can only contain alphanumeric and space characters.')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Allow New Apps Audit Events', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'Allow New Apps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = 'Merge Supplemental Policies', ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,

        [ValidatePattern('\.xml$')]
        [ValidateScript({
                # Validate the Policy file to make sure the user isn't accidentally trying to
                # Edit a Signed policy using Edit-WDACConfig cmdlet which is only made for Unsigned policies
                $XmlTest = [System.Xml.XmlDocument](Get-Content -Path $_)
                $RedFlag1 = $XmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                $RedFlag2 = $XmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                $RedFlag3 = $XmlTest.SiPolicy.PolicyID
                $CurrentPolicyIDs = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' }).policyID | ForEach-Object -Process { "{$_}" }
                if (!$RedFlag1 -and !$RedFlag2) {
                    # Ensure the selected base policy xml file is deployed
                    if ($CurrentPolicyIDs -contains $RedFlag3) {
                        return $True
                    }
                    else { throw "The currently selected policy xml file isn't deployed." }
                }
                # This throw is shown only when User added a Signed policy xml file for Unsigned policy file path property in user configuration file
                # Without this, the error shown would be vague: The variable cannot be validated because the value System.String[] is not a valid value for the PolicyPath variable.
                else { throw 'The policy xml file in User Configurations for UnsignedPolicyPath is a Signed policy.' }
            }, ErrorMessage = 'The selected policy xml file is Signed. Please use Edit-SignedWDACConfig cmdlet to edit Signed policies.')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps', ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Merge Supplemental Policies', ValueFromPipelineByPropertyName = $true)]
        [System.String]$PolicyPath,

        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path -Path $_ -PathType 'Leaf' }, ErrorMessage = 'The path you selected is not a file path.')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Merge Supplemental Policies', ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = 'Merge Supplemental Policies')]
        [System.Management.Automation.SwitchParameter]$KeepOldSupplementalPolicies,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')]
        [System.String]$Level = 'FilePublisher',

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps')]
        [System.String[]]$Fallbacks = 'Hash',

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

        [ValidateRange(1024KB, 18014398509481983KB)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')]
        [System.Int64]$LogSize,

        [parameter(Mandatory = $false, ParameterSetName = 'Allow New Apps Audit Events')][System.Management.Automation.SwitchParameter]$IncludeDeletedFiles,

        [ValidateSet([BasePolicyNamez])]
        [Parameter(Mandatory = $true, ParameterSetName = 'Update Base Policy')][System.String[]]$CurrentBasePolicyName,

        [ValidateSet('AllowMicrosoft_Plus_Block_Rules', 'Lightly_Managed_system_Policy', 'DefaultWindows_WithBlockRules')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Update Base Policy')][System.String]$NewBasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = 'Update Base Policy')][System.Management.Automation.SwitchParameter]$RequireEVSigners,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Detecting if Verbose switch is used
        $PSBoundParameters.Verbose.IsPresent ? ([System.Boolean]$Verbose = $true) : ([System.Boolean]$Verbose = $false) | Out-Null

        # Importing the $PSDefaultParameterValues to the current session, prior to everything else
        . "$ModuleRootPath\CoreExt\PSDefaultParameterValues.ps1"

        # Importing the required sub-modules
        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Update-self.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-GlobalRootDrives.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Write-ColorfulText.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Set-LogSize.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Test-FilePath.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-AuditEventLogsProcessing.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-EmptyPolicy.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-RuleRefs.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-FileRules.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\Get-BlockRulesMeta.psm1" -Force
        Import-Module -FullyQualifiedName "$ModuleRootPath\Shared\New-SnapBackGuarantee.psm1" -Force

        # if -SkipVersionCheck wasn't passed, run the updater
        if (-NOT $SkipVersionCheck) { Update-self -InvocationStatement $MyInvocation.Statement }

        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

        #Region User-Configurations-Processing-Validation
        # make sure the ParameterSet being used has PolicyPath parameter - Then enforces "mandatory" attribute for the parameter
        if ($PSCmdlet.ParameterSetName -in 'Allow New Apps Audit Events', 'Allow New Apps', 'Merge Supplemental Policies') {
            # If any of these parameters, that are mandatory for all of the position 0 parameters, isn't supplied by user
            if (!$PolicyPath) {
                # Read User configuration file if it exists
                $UserConfig = Get-Content -Path "$UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue
                if ($UserConfig) {
                    # Validate the Json file and read its content to make sure it's not corrupted
                    try { $UserConfig = $UserConfig | ConvertFrom-Json }
                    catch {
                        Write-Error -Message 'User Configuration Json file is corrupted, deleting it...' -ErrorAction Continue
                        Remove-CommonWDACConfig
                    }
                }
            }
            # If PolicyPath has no values
            if (!$PolicyPath) {
                if ($UserConfig.UnsignedPolicyPath) {
                    # validate each policyPath read from user config file
                    if (Test-Path -Path $($UserConfig.UnsignedPolicyPath)) {
                        $PolicyPath = $UserConfig.UnsignedPolicyPath
                    }
                    else {
                        throw 'The currently saved value for UnsignedPolicyPath in user configurations is invalid.'
                    }
                }
                else {
                    throw 'PolicyPath parameter cannot be empty and no valid configuration was found for UnsignedPolicyPath.'
                }
            }
        }
        #Endregion User-Configurations-Processing-Validation

        # argument tab auto-completion and ValidateSet for Policy names
        Class BasePolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $BasePolicyNamez = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' } | Where-Object -FilterScript { $_.PolicyID -eq $_.BasePolicyID }).Friendlyname

                return [System.String[]]$BasePolicyNamez
            }
        }

        # argument tab auto-completion and ValidateSet for Fallbacks
        Class Fallbackz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Fallbackz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
                return [System.String[]]$Fallbackz
            }
        }

        # argument tab auto-completion and ValidateSet for level
        Class Levelz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Levelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
                return [System.String[]]$Levelz
            }
        }

        function Update-BasePolicyToEnforced {
            <#
            .SYNOPSIS
                A helper function used to redeploy the base policy in Enforced mode
            .INPUTS
                None. This function uses the global variables $PolicyName and $PolicyID
            .OUTPUTS
                System.String
            #>
            [CmdletBinding()]
            param()

            # Deploy Enforced mode CIP
            &'C:\Windows\System32\CiTool.exe' --update-policy '.\EnforcedMode.cip' -json | Out-Null
            Write-ColorfulText -Color Lavender -InputText 'The Base policy with the following details has been Re-Deployed in Enforced Mode:'
            Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
            Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"
            # Remove Enforced Mode CIP
            Remove-Item -Path '.\EnforcedMode.cip' -Force
        }
    }

    process {

        if ($AllowNewApps) {

            # remove any possible files from previous runs
            Write-Verbose -Message 'Removing any possible files from previous runs'
            Remove-Item -Path '.\ProgramDir_ScanResults*.xml' -Force -ErrorAction SilentlyContinue
            Remove-Item -Path ".\SupplementalPolicy $SuppPolicyName.xml" -Force -ErrorAction SilentlyContinue

            # An empty array that holds the Policy XML files - This array will eventually be used to create the final Supplemental policy
            [System.Object[]]$PolicyXMLFilesArray = @()

            #Initiate Live Audit Mode

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 8
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 9 -Activity 'Creating Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Creating a copy of the original policy in Temp folder so that the original one will be unaffected
            Write-Verbose -Message 'Creating a copy of the original policy in Temp folder so that the original one will be unaffected'
            # Get the policy file name
            [System.String]$PolicyFileName = Split-Path -Path $PolicyPath -Leaf
            # make sure no file with the same name already exists in Temp folder
            Remove-Item -Path "$UserTempDirectoryPath\$PolicyFileName" -Force -ErrorAction SilentlyContinue
            Copy-Item -Path $PolicyPath -Destination $UserTempDirectoryPath -Force
            [System.String]$PolicyPath = "$UserTempDirectoryPath\$PolicyFileName"

            Write-Verbose -Message 'Retrieving the Base policy name and ID'
            $Xml = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
            [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
            [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string

            # Remove any cip file if there is any
            Write-Verbose -Message 'Removing any cip file if there is any in the current working directory'
            Remove-Item -Path '.\*.cip' -Force -ErrorAction SilentlyContinue

            Write-Verbose -Message 'Creating Audit Mode CIP'
            # Add Audit mode policy rule option
            Set-RuleOption -FilePath $PolicyPath -Option 3
            # Create CIP for Audit Mode
            ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath '.\AuditMode.cip' | Out-Null

            Write-Verbose -Message 'Creating Enforced Mode CIP'
            # Remove Audit mode policy rule option
            Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete
            # Create CIP for Enforced Mode
            ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath '.\EnforcedMode.cip' | Out-Null

            #Region Snap-Back-Guarantee
            Write-Verbose -Message 'Creating Enforced Mode SnapBack guarantee'
            New-SnapBackGuarantee -Path (Get-Location).Path

            $CurrentStep++
            Write-Progress -Id 9 -Activity 'Deploying the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the Audit mode CIP'
            &'C:\Windows\System32\CiTool.exe' --update-policy '.\AuditMode.cip' -json | Out-Null

            Write-ColorfulText -Color Lavender -InputText 'The Base policy with the following details has been Re-Deployed in Audit Mode:'
            Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
            Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"

            # Remove Audit Mode CIP
            Remove-Item -Path '.\AuditMode.cip' -Force
            #Endregion Snap-Back-Guarantee

            # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode
            Try {
                #Region User-Interaction

                $CurrentStep++
                Write-Progress -Id 9 -Activity 'Waiting for user input' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-ColorfulText -Color Pink -InputText 'Audit mode deployed, start installing your programs now'
                Write-ColorfulText -Color HotPink -InputText 'When you have finished installing programs, Press Enter to start selecting program directories to scan'
                Pause

                # Store the program paths that user browses for in an array
                [System.IO.DirectoryInfo[]]$ProgramsPaths = @()
                Write-Host -Object 'Select program directories to scan' -ForegroundColor Cyan

                # Showing folder picker GUI to the user for folder path selection
                do {
                    [System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null
                    [System.Windows.Forms.FolderBrowserDialog]$OBJ = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
                    $OBJ.InitialDirectory = "$env:SystemDrive"
                    $OBJ.Description = $Description
                    [System.Windows.Forms.Form]$Spawn = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }
                    [System.String]$Show = $OBJ.ShowDialog($Spawn)
                    If ($Show -eq 'OK') { $ProgramsPaths += $OBJ.SelectedPath }
                    Else { break }
                }
                while ($true)
                #Endregion User-Interaction

                # Make sure User browsed for at least 1 directory, otherwise exit
                if ($ProgramsPaths.count -eq 0) {
                    # Finally block will be triggered to Re-Deploy Base policy in Enforced mode
                    Throw 'No program folder was selected, reverting the changes and quitting...'
                }
            }
            catch {
                # Complete the progress bar if there was an error, such as user not selecting any folders
                Write-Progress -Id 9 -Activity 'Complete.' -Completed

                # Show any extra info about any possible error that might've occurred
                Throw $_
            }
            finally {
                # Deploy Enforced mode CIP
                Write-Verbose -Message 'Finally Block Running'
                Update-BasePolicyToEnforced

                # Enforced Mode Snapback removal after base policy has already been successfully re-enforced
                Write-Verbose -Message 'Removing the SnapBack guarantee because the base policy has been successfully re-enforced'

                # For CMD Method
                Unregister-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Confirm:$false
                Remove-Item -Path 'C:\EnforcedModeSnapBack.cmd' -Force
            }

            Write-Host -Object 'Here are the paths you selected:' -ForegroundColor Yellow
            $ProgramsPaths | ForEach-Object -Process { $_.FullName }

            # Scan each of the folder paths that user selected
            $CurrentStep++
            Write-Progress -Id 9 -Activity 'Scanning user selected folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Scanning each of the folder paths that user selected'
            for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                    FilePath               = ".\ProgramDir_ScanResults$($i).xml"
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

            # Merge-CiPolicy accepts arrays - collecting all the policy files created by scanning user specified folders
            Write-Verbose -Message 'Collecting all the policy files created by scanning user specified folders'

            foreach ($file in (Get-ChildItem -File -Path '.\' -Filter 'ProgramDir_ScanResults*.xml')) {
                $PolicyXMLFilesArray += $file.FullName
            }

            Write-Verbose -Message 'The following policy xml files are going to be merged into the final Supplemental policy and be deployed on the system:'
            $PolicyXMLFilesArray | ForEach-Object -Process { Write-Verbose -Message "$_" }

            # Merge all of the policy XML files in the array into the final Supplemental policy
            $CurrentStep++
            Write-Progress -Id 9 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Merging all of the policy XML files in the array into the final Supplemental policy'
            Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\SupplementalPolicy $SuppPolicyName.xml" | Out-Null

            Write-Verbose -Message 'Removing the ProgramDir_ScanResults* xml files'
            Remove-Item -Path '.\ProgramDir_ScanResults*.xml' -Force

            #Region Supplemental-policy-processing-and-deployment
            $CurrentStep++
            Write-Progress -Id 9 -Activity 'Creating Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Supplemental policy processing and deployment'

            Write-Verbose -Message 'Getting the path of the Supplemental policy'
            [System.String]$SuppPolicyPath = ".\SupplementalPolicy $SuppPolicyName.xml"

            Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
            [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
            $SuppPolicyID = $SuppPolicyID.Substring(11)

            # Make sure policy rule options that don't belong to a Supplemental policy don't exist
            Write-Verbose -Message 'Making sure policy rule options that do not belong to a Supplemental policy do not exist'
            @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }

            Write-Verbose -Message 'Setting HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath $SuppPolicyPath

            Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version '1.0.0.0'

            Write-Verbose -Message 'Convert the Supplemental policy to a CIP file'
            ConvertFrom-CIPolicy -XmlFilePath $SuppPolicyPath -BinaryFilePath "$SuppPolicyID.cip" | Out-Null

            $CurrentStep++
            Write-Progress -Id 9 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the Supplemental policy'
            &'C:\Windows\System32\CiTool.exe' --update-policy ".\$SuppPolicyID.cip" -json | Out-Null

            Write-ColorfulText -Color Lavender -InputText 'Supplemental policy with the following details has been deployed in Enforced Mode:'
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyName = $SuppPolicyName"
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $SuppPolicyID"

            Write-Verbose -Message 'Removing the Supplemental policy CIP file after deployment'
            Remove-Item -Path ".\$SuppPolicyID.cip" -Force

            # Remove the policy xml file in Temp folder we created earlier
            Write-Verbose -Message 'Removing the policy xml file in Temp folder we created earlier'
            Remove-Item -Path $PolicyPath -Force

            #Endregion Supplemental-policy-processing-and-deployment

            Write-Progress -Id 9 -Activity 'Complete.' -Completed
        }

        if ($AllowNewAppsAuditEvents) {

            # Change Code Integrity event logs size
            if ($AllowNewAppsAuditEvents -and $LogSize) {
                Write-Verbose -Message 'Changing Code Integrity event logs size'
                Set-LogSize -LogSize $LogSize
            }

            # Make sure there is no leftover from previous runs
            Write-Verbose -Message 'Removing any possible files from previous runs'
            Remove-Item -Path '.\ProgramDir_ScanResults*.xml' -Force -ErrorAction SilentlyContinue
            Remove-Item -Path ".\SupplementalPolicy $SuppPolicyName.xml" -Force -ErrorAction SilentlyContinue

            # Get the current date so that instead of the entire event viewer logs, only audit logs created after running this module will be captured
            Write-Verbose -Message 'Getting the current date'
            [System.DateTime]$Date = Get-Date

            # An empty array that holds the Policy XML files - This array will eventually be used to create the final Supplemental policy
            [System.Object[]]$PolicyXMLFilesArray = @()

            #Initiate Live Audit Mode

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 9
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 10 -Activity 'Creating the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            # Creating a copy of the original policy in Temp folder so that the original one will be unaffected
            Write-Verbose -Message 'Creating a copy of the original policy in Temp folder so that the original one will be unaffected'
            # Get the policy file name
            [System.String]$PolicyFileName = Split-Path -Path $PolicyPath -Leaf
            # make sure no file with the same name already exists in Temp folder
            Remove-Item -Path "$UserTempDirectoryPath\$PolicyFileName" -Force -ErrorAction SilentlyContinue
            Copy-Item -Path $PolicyPath -Destination $UserTempDirectoryPath -Force
            [System.String]$PolicyPath = "$UserTempDirectoryPath\$PolicyFileName"

            Write-Verbose -Message 'Retrieving the Base policy name and ID'
            $Xml = [System.Xml.XmlDocument](Get-Content -Path $PolicyPath)
            [System.String]$PolicyID = $Xml.SiPolicy.PolicyID
            [System.String]$PolicyName = ($Xml.SiPolicy.Settings.Setting | Where-Object -FilterScript { $_.provider -eq 'PolicyInfo' -and $_.valuename -eq 'Name' -and $_.key -eq 'Information' }).value.string

            # Remove any cip file if there is any
            Write-Verbose -Message 'Removing any cip file if there is any in the current working directory'
            Remove-Item -Path '.\*.cip' -Force -ErrorAction SilentlyContinue

            Write-Verbose -Message 'Creating Audit Mode CIP'
            # Add Audit mode policy rule option
            Set-RuleOption -FilePath $PolicyPath -Option 3
            # Create CIP for Audit Mode
            ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath '.\AuditMode.cip' | Out-Null

            Write-Verbose -Message 'Creating Enforced Mode CIP'
            # Remove Audit mode policy rule option
            Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete
            # Create CIP for Enforced Mode
            ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath '.\EnforcedMode.cip' | Out-Null

            #Region Snap-Back-Guarantee
            Write-Verbose -Message 'Creating Enforced Mode SnapBack guarantee'
            New-SnapBackGuarantee -Path (Get-Location).Path

            $CurrentStep++
            Write-Progress -Id 10 -Activity 'Deploying the Audit mode policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the Audit mode CIP'
            &'C:\Windows\System32\CiTool.exe' --update-policy '.\AuditMode.cip' -json | Out-Null

            Write-ColorfulText -Color Lavender -InputText 'The Base policy with the following details has been Re-Deployed in Audit Mode:'
            Write-ColorfulText -Color MintGreen -InputText "PolicyName = $PolicyName"
            Write-ColorfulText -Color MintGreen -InputText "PolicyGUID = $PolicyID"

            # Remove Audit Mode CIP
            Remove-Item -Path '.\AuditMode.cip' -Force
            #Endregion Snap-Back-Guarantee

            # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode
            Try {
                #Region User-Interaction
                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Waiting for user input' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-ColorfulText -Color Pink -InputText 'Audit mode deployed, start installing your programs now'
                Write-ColorfulText -Color HotPink -InputText 'When you have finished installing programs, Press Enter to start selecting program directories to scan'
                Pause

                # Store the program paths that user browses for in an array
                [System.IO.DirectoryInfo[]]$ProgramsPaths = @()
                Write-Host -Object 'Select program directories to scan' -ForegroundColor Cyan

                # Showing folder picker GUI to the user for folder path selection
                do {
                    [System.Reflection.Assembly]::LoadWithPartialName('System.windows.forms') | Out-Null
                    [System.Windows.Forms.FolderBrowserDialog]$OBJ = New-Object -TypeName System.Windows.Forms.FolderBrowserDialog
                    $OBJ.InitialDirectory = "$env:SystemDrive"
                    $OBJ.Description = $Description
                    [System.Windows.Forms.Form]$Spawn = New-Object -TypeName System.Windows.Forms.Form -Property @{TopMost = $true }
                    [System.String]$Show = $OBJ.ShowDialog($Spawn)
                    If ($Show -eq 'OK') { $ProgramsPaths += $OBJ.SelectedPath }
                    Else { break }
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
                Write-Progress -Id 10 -Activity 'Scanning event logs to create policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Extracting the array content from Get-AuditEventLogsProcessing function
                $AuditEventLogsProcessingResults = Get-AuditEventLogsProcessing -Date $Date

                # Only create policy for files that are available on the disk (based on Event viewer logs)
                # but weren't in user-selected program path(s), if there are any
                if ($AuditEventLogsProcessingResults.AvailableFilesPaths) {

                    # Using the function to find out which files are not in the user-selected path(s), if any, to only scan those by first copying them to another directory
                    # this prevents duplicate rule creation and double file copying
                    $TestFilePathResults = (Test-FilePath -FilePath $AuditEventLogsProcessingResults.AvailableFilesPaths -DirectoryPath $ProgramsPaths).path | Select-Object -Unique

                    Write-Verbose -Message "$($TestFilePathResults.count) file(s) have been found in event viewer logs that don't exist in any of the folder paths you selected."

                    # Another check to make sure there were indeed files found in Event viewer logs but weren't in any of the user-selected path(s)
                    if ($TestFilePathResults) {

                        # Create a folder in Temp directory to copy the files that are not included in user-selected program path(s)
                        # but detected in Event viewer audit logs, scan that folder, and in the end delete it
                        New-Item -Path "$UserTempDirectoryPath\TemporaryScanFolderForEventViewerFiles" -ItemType Directory -Force | Out-Null

                        Write-Verbose -Message 'The following file(s) are being copied to the TEMP directory for scanning because they were found in event logs but did not exist in any of the user-selected paths:'
                        $TestFilePathResults | ForEach-Object -Process {
                            Write-Verbose -Message "$_"
                            Copy-Item -Path $_ -Destination "$UserTempDirectoryPath\TemporaryScanFolderForEventViewerFiles\" -Force -ErrorAction SilentlyContinue
                        }

                        # Create a policy XML file for available files on the disk

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        [System.Collections.Hashtable]$AvailableFilesOnDiskPolicyMakerHashTable = @{
                            FilePath               = '.\RulesForFilesNotInUserSelectedPaths.xml'
                            ScanPath               = "$UserTempDirectoryPath\TemporaryScanFolderForEventViewerFiles\"
                            Level                  = $Level -eq 'FilePath' ? 'FilePublisher' : $Level # Since FilePath will not be valid for files scanned in the temp directory (because they weren't in any user-selected paths), using FilePublisher as level in case user chose FilePath as level
                            Fallback               = $Fallbacks -eq 'FilePath' ? 'Hash' : $Fallbacks # Since FilePath will not be valid for files scanned in the temp directory (because they weren't in any user-selected paths), using Hash as Fallback in case user chose FilePath as Fallback
                            MultiplePolicyFormat   = $true
                            UserWriteablePaths     = $true
                            AllowFileNameFallbacks = $true
                        }
                        # Assess user input parameters and add the required parameters to the hash table
                        if ($SpecificFileNameLevel) { $AvailableFilesOnDiskPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                        if ($NoScript) { $AvailableFilesOnDiskPolicyMakerHashTable['NoScript'] = $true }
                        if (!$NoUserPEs) { $AvailableFilesOnDiskPolicyMakerHashTable['UserPEs'] = $true }

                        # Create the supplemental policy via parameter splatting
                        Write-Verbose -Message 'Creating a policy file for files that are available on the disk but were not in user-selected program path(s)'
                        New-CIPolicy @AvailableFilesOnDiskPolicyMakerHashTable

                        # Add the policy XML file to the array that holds policy XML files
                        $PolicyXMLFilesArray += '.\RulesForFilesNotInUserSelectedPaths.xml'

                        # Delete the Temporary folder in the TEMP folder
                        Write-Verbose -Message 'Deleting the Temporary folder in the TEMP folder'
                        Remove-Item -Recurse -Path "$UserTempDirectoryPath\TemporaryScanFolderForEventViewerFiles\" -Force
                    }
                }

                # Only create policy for files that are on longer available on the disk if there are any and
                # if user chose to include deleted files in the final supplemental policy
                if ($AuditEventLogsProcessingResults.DeletedFileHashes -and $IncludeDeletedFiles) {

                    Write-Verbose -Message 'Attempting to create a policy for files that are no longer available on the disk but were detected in event viewer logs'

                    # Displaying the unique values and count. Even though the DeletedFileHashesEventsPolicy.xml will have many duplicates, the final supplemental policy that will be deployed on the system won't have any duplicates
                    # Because Merge-CiPolicy will automatically take care of removing them
                    Write-Verbose -Message "$(($AuditEventLogsProcessingResults.DeletedFileHashes.'File Name' | Select-Object -Unique).count) file(s) have been found in event viewer logs that were run during Audit phase but are no longer on the disk, they are as follows:"
                    $AuditEventLogsProcessingResults.DeletedFileHashes.'File Name' | Select-Object -Unique | ForEach-Object -Process {
                        Write-Verbose -Message "$_"
                    }

                    Write-Verbose -Message 'Creating FileRules and RuleRefs for files that are no longer available on the disk but were detected in event viewer logs'
                    [System.String]$FileRulesHashesResults = Get-FileRules -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes
                    [System.String]$RuleRefsHashesResults = (Get-RuleRefs -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes).Trim()

                    # Save the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the current working directory for debugging purposes
                    Write-Verbose -Message 'Saving the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the current working directory for debugging purposes'
                    $FileRulesHashesResults + $RuleRefsHashesResults | Out-File -FilePath FileRulesAndFileRefs.txt -Force

                    # Put the Rules and RulesRefs in an empty policy file
                    Write-Verbose -Message 'Putting the Rules and RulesRefs in an empty policy file'
                    New-EmptyPolicy -RulesContent $FileRulesHashesResults -RuleRefsContent $RuleRefsHashesResults | Out-File -FilePath .\DeletedFileHashesEventsPolicy.xml -Force

                    # adding the policy file that consists of rules from audit even logs, to the array
                    Write-Verbose -Message 'Adding the policy file (DeletedFileHashesEventsPolicy.xml) that consists of rules from audit even logs, to the array of XML files'
                    $PolicyXMLFilesArray += '.\DeletedFileHashesEventsPolicy.xml'
                }
                #Endregion EventCapturing

                #Region Process-Program-Folders-From-User-input
                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Scanning user selected folders' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Write-Verbose -Message 'Scanning each of the folder paths that user selected'

                for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                    # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                    [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                        FilePath               = ".\ProgramDir_ScanResults$($i).xml"
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

                # Merge-CiPolicy accepts arrays - collecting all the policy files created by scanning user specified folders
                Write-Verbose -Message 'Collecting all the policy files created by scanning user specified folders'

                foreach ($file in (Get-ChildItem -File -Path '.\' -Filter 'ProgramDir_ScanResults*.xml')) {
                    $PolicyXMLFilesArray += $file.FullName
                }
                #Endregion Process-Program-Folders-From-User-input

                #Region Kernel-protected-files-automatic-detection-and-allow-rule-creation
                # This part takes care of Kernel protected files such as the main executable of the games installed through Xbox app
                # For these files, only Kernel can get their hashes, it passes them to event viewer and we take them from event viewer logs
                # Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fail and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them

                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Checking for Kernel protected files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

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
                            # If the executable is protected, it will throw an exception and the script will continue to the next one
                            # Making sure only the right file is captured by narrowing down the error type.
                            # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException
                            catch [System.UnauthorizedAccessException] {
                                $ExesWithNoHash += $Exe
                            }
                        }
                    }
                }

                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Checking for extra files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                # Only proceed if any kernel protected file(s) were found in any of the user-selected directory path(s)
                if ($ExesWithNoHash) {

                    Write-Verbose -Message 'The following Kernel protected files detected, creating allow rules for them:'
                    $ExesWithNoHash | ForEach-Object -Process { Write-Verbose -Message "$_" }

                    [System.Management.Automation.ScriptBlock]$KernelProtectedHashesBlock = {
                        foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.TimeCreated -ge $Date } ) {
                            $Xml = [System.Xml.XmlDocument]$event.toxml()
                            $Xml.event.eventdata.data |
                            ForEach-Object -Begin { $Hash = @{} } -Process { $hash[$_.name] = $_.'#text' } -End { [pscustomobject]$hash } |
                            ForEach-Object -Process {
                                if ($_.'File Name' -match ($pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$')) {
                                    $hardDiskVolumeNumber = $Matches[1]
                                    $remainingPath = $Matches[2]
                                    $getletter = Get-GlobalRootDrives | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$hardDiskVolumeNumber" }
                                    $usablePath = "$($getletter.DriveLetter)$remainingPath"
                                    $_.'File Name' = $_.'File Name' -replace $pattern, $usablePath
                                } # Check if file is currently on the disk
                                if (Test-Path -Path $_.'File Name') {
                                    # Check if the file exits in the $ExesWithNoHash array
                                    if ($ExesWithNoHash -contains $_.'File Name') {
                                        $_ | Select-Object -Property FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                                    }
                                }
                            }
                        }
                    }

                    $KernelProtectedHashesBlockResults = Invoke-Command -ScriptBlock $KernelProtectedHashesBlock

                    # Only proceed further if any hashes belonging to the detected kernel protected files were found in Event viewer
                    # If none is found then skip this part, because user didn't run those files/programs when audit mode was turned on in base policy, so no hash was found in audit logs
                    if ($KernelProtectedHashesBlockResults) {

                        # Save the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the current working directory for debugging purposes
                            (Get-FileRules -HashesArray $KernelProtectedHashesBlockResults) + (Get-RuleRefs -HashesArray $KernelProtectedHashesBlockResults) | Out-File -FilePath KernelProtectedFiles.txt -Force

                        # Put the Rules and RulesRefs in an empty policy file
                        New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $KernelProtectedHashesBlockResults) -RuleRefsContent (Get-RuleRefs -HashesArray $KernelProtectedHashesBlockResults) | Out-File -FilePath .\KernelProtectedFiles.xml -Force

                        # adding the policy file  to the array of xml files
                        $PolicyXMLFilesArray += '.\KernelProtectedFiles.xml'
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

                # Merge all of the policy XML files in the array into the final Supplemental policy
                $CurrentStep++
                Write-Progress -Id 10 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

                Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\SupplementalPolicy $SuppPolicyName.xml" | Out-Null

                # Delete these extra files unless user uses -Debug parameter
                if (!$Debug) {
                    Remove-Item -Path '.\RulesForFilesNotInUserSelectedPaths.xml', '.\ProgramDir_ScanResults*.xml' -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path '.\KernelProtectedFiles.xml', '.\DeletedFileHashesEventsPolicy.xml' -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path '.\KernelProtectedFiles.txt', '.\FileRulesAndFileRefs.txt' -Force -ErrorAction SilentlyContinue
                }
            }
            # Unlike AllowNewApps parameter, AllowNewAppsAuditEvents parameter performs Event viewer scanning and kernel protected files detection
            # So the base policy enforced mode snap back can't happen any sooner than this point
            catch {
                # Complete the progress bar if there was an error, such as user not selecting any folders
                Write-Progress -Id 10 -Activity 'Complete.' -Completed

                # Show any extra info about any possible error that might've occurred
                Throw $_
            }
            finally {
                # Deploy Enforced mode CIP
                Write-Verbose -Message 'Finally Block Running'
                Update-BasePolicyToEnforced

                # Enforced Mode Snapback removal after base policy has already been successfully re-enforced
                Write-Verbose -Message 'Removing the SnapBack guarantee because the base policy has been successfully re-enforced'
                Unregister-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Confirm:$false
                Remove-Item -Path 'C:\EnforcedModeSnapBack.cmd' -Force
            }

            #Region Supplemental-policy-processing-and-deployment

            Write-Verbose -Message 'Supplemental policy processing and deployment'
            [System.String]$SuppPolicyPath = ".\SupplementalPolicy $SuppPolicyName.xml"

            Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
            [System.String]$SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
            $SuppPolicyID = $SuppPolicyID.Substring(11)

            # Make sure policy rule options that don't belong to a Supplemental policy don't exist
            Write-Verbose -Message 'Making sure policy rule options that do not belong to a Supplemental policy do not exist'
            @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }

            Write-Verbose -Message 'Setting HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath $SuppPolicyPath

            Write-Verbose -Message 'Setting the Supplemental policy version to 1.0.0.0'
            Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version '1.0.0.0'

            Write-Verbose -Message 'Convert the Supplemental policy to a CIP file'
            ConvertFrom-CIPolicy -XmlFilePath $SuppPolicyPath -BinaryFilePath "$SuppPolicyID.cip" | Out-Null

            $CurrentStep++
            Write-Progress -Id 10 -Activity 'Deploying the Supplemental policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the Supplemental policy'
            &'C:\Windows\System32\CiTool.exe' --update-policy ".\$SuppPolicyID.cip" -json | Out-Null

            Write-ColorfulText -Color Lavender -InputText 'Supplemental policy with the following details has been deployed in Enforced Mode:'
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyName = $SuppPolicyName"
            Write-ColorfulText -Color MintGreen -InputText "SupplementalPolicyGUID = $SuppPolicyID"

            Write-Verbose -Message 'Removing the Supplemental policy CIP file after deployment'
            Remove-Item -Path ".\$SuppPolicyID.cip" -Force

            # Remove the policy xml file in Temp folder we created earlier
            Remove-Item -Path $PolicyPath -Force

            #Endregion Supplemental-policy-processing-and-deployment

            Write-Progress -Id 10 -Activity 'Complete.' -Completed
        }

        if ($MergeSupplementalPolicies) {

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 5
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 11 -Activity 'Verifying the input files' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            #Region Input-policy-verification
            Write-Verbose -Message 'Verifying the input policy files'
            foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                Write-Verbose -Message "Getting policy ID and type of: $SuppPolicyPath"
                $Supplementalxml = [System.Xml.XmlDocument](Get-Content -Path $SuppPolicyPath)
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
            Write-Progress -Id 11 -Activity 'Merging the policies' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Merging the Supplemental policies into a single policy file'
            Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath "$SuppPolicyName.xml" | Out-Null

            # Remove the deployed Supplemental policies that user selected from the system, because we're going to deploy the new merged policy that contains all of them
            $CurrentStep++
            Write-Progress -Id 11 -Activity 'Removing old policies from the system' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Removing the deployed Supplemental policies that user selected from the system'
            foreach ($SuppPolicyPath in $SuppPolicyPaths) {

                # Get the policy ID of the currently selected Supplemental policy
                $Supplementalxml = [System.Xml.XmlDocument](Get-Content -Path $SuppPolicyPath)
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
            Write-Progress -Id 11 -Activity 'Configuring the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Preparing the final merged Supplemental policy for deployment'
            Write-Verbose -Message 'Converting the policy to a Supplemental policy type and resetting its ID'
            $SuppPolicyID = Set-CIPolicyIdInfo -FilePath "$SuppPolicyName.xml" -ResetPolicyID -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
            $SuppPolicyID = $SuppPolicyID.Substring(11)

            Write-Verbose -Message 'Setting HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath "$SuppPolicyName.xml"

            Write-Verbose -Message 'Converting the Supplemental policy to a CIP file'
            ConvertFrom-CIPolicy -XmlFilePath "$SuppPolicyName.xml" -BinaryFilePath "$SuppPolicyID.cip" | Out-Null

            $CurrentStep++
            Write-Progress -Id 11 -Activity 'Deploying the final policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the Supplemental policy'
            &'C:\Windows\System32\CiTool.exe' --update-policy "$SuppPolicyID.cip" -json | Out-Null

            Write-ColorfulText -Color TeaGreen -InputText "The Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones.`nSystem Restart is not immediately needed but eventually required to finish the removal of the previous individual Supplemental policies."

            Write-Verbose -Message 'Removing the Supplemental policy CIP file after deployment'
            Remove-Item -Path "$SuppPolicyID.cip" -Force

            Write-Progress -Id 11 -Activity 'Complete.' -Completed
        }

        if ($UpdateBasePolicy) {

            # The total number of the main steps for the progress bar to render
            [System.Int16]$TotalSteps = 5
            [System.Int16]$CurrentStep = 0

            $CurrentStep++
            Write-Progress -Id 12 -Activity 'Getting the block rules' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Getting the Microsoft recommended block rules by calling the Get-BlockRulesMeta function'
            Get-BlockRulesMeta 6> $null

            $CurrentStep++
            Write-Progress -Id 12 -Activity 'Determining the policy type' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Determining the type of the new base policy'
            switch ($NewBasePolicyType) {
                'AllowMicrosoft_Plus_Block_Rules' {
                    Write-Verbose -Message 'The new base policy type is AllowMicrosoft_Plus_Block_Rules'

                    Write-Verbose -Message 'Copying the AllowMicrosoft.xml template policy file to the current working directory'
                    Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination '.\AllowMicrosoft.xml' -Force

                    Write-Verbose -Message 'Merging the AllowMicrosoft.xml and Microsoft recommended block rules into a single policy file'
                    Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null

                    Write-Verbose -Message 'Setting the policy name'
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Allow Microsoft Plus Block Rules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"

                    Write-Verbose -Message 'Setting the policy rule options'
                    @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }

                    Write-Verbose -Message 'Removing the unnecessary policy rule options'
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }
                }
                'Lightly_Managed_system_Policy' {
                    Write-Verbose -Message 'The new base policy type is Lightly_Managed_system_Policy'

                    Write-Verbose -Message 'Copying the AllowMicrosoft.xml template policy file to the current working directory'
                    Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination '.\AllowMicrosoft.xml' -Force

                    Write-Verbose -Message 'Merging the AllowMicrosoft.xml and Microsoft recommended block rules into a single policy file'
                    Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null

                    Write-Verbose -Message 'Setting the policy name'
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Signed And Reputable policy refreshed on $(Get-Date -Format 'MM-dd-yyyy')"

                    Write-Verbose -Message 'Setting the policy rule options'
                    @(0, 2, 5, 6, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }

                    Write-Verbose -Message 'Removing the unnecessary policy rule options'
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }

                    # Configure required services for ISG authorization
                    Write-Verbose -Message 'Configuring required services for ISG authorization'
                    Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -Wait -NoNewWindow
                    Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -Wait -NoNewWindow
                }
                'DefaultWindows_WithBlockRules' {
                    Write-Verbose -Message 'The new base policy type is DefaultWindows_WithBlockRules'

                    Write-Verbose -Message 'Copying the DefaultWindows.xml template policy file to the current working directory'
                    Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination '.\DefaultWindows_Enforced.xml' -Force

                    if ($PSHOME -notlike 'C:\Program Files\WindowsApps\*') {
                        Write-Verbose -Message 'Scanning the PowerShell core directory '

                        Write-ColorfulText -Color HotPink -InputText 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'

                        New-CIPolicy -ScanPath $PSHOME -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath .\AllowPowerShell.xml

                        Write-Verbose -Message 'Merging the DefaultWindows.xml, AllowPowerShell.xml, SignTool.xml and Microsoft recommended block rules into a single policy file'
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }
                    else {
                        Write-Verbose -Message 'Not including the PowerShell core directory in the policy'
                        Write-Verbose -Message 'Merging the DefaultWindows.xml, SignTool.xml and Microsoft recommended block rules into a single policy file'
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }

                    Write-Verbose -Message 'Setting the policy name'
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Default Windows Plus Block Rules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"

                    Write-Verbose -Message 'Setting the policy rule options'
                    @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }

                    Write-Verbose -Message 'Removing the unnecessary policy rule options'
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }
                }
            }

            $CurrentStep++
            Write-Progress -Id 12 -Activity 'Configuring the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            if ($UpdateBasePolicy -and $RequireEVSigners) {
                Write-Verbose -Message 'Adding the EV Signers rule option to the base policy'
                Set-RuleOption -FilePath .\BasePolicy.xml -Option 8
            }

            # Remove the extra files create during module operation that are no longer necessary
            if (!$Debug) {
                Remove-Item -Path '.\AllowPowerShell.xml', '.\DefaultWindows_Enforced.xml', '.\AllowMicrosoft.xml' -Force -ErrorAction SilentlyContinue
                Remove-Item -Path '.\Microsoft recommended block rules.xml' -Force
            }

            # Get the policy ID of the currently deployed base policy based on the policy name that user selected
            Write-Verbose -Message 'Getting the policy ID of the currently deployed base policy based on the policy name that user selected'
            [System.String]$CurrentID = ((&'C:\Windows\System32\CiTool.exe' -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.IsSystemPolicy -ne 'True' } | Where-Object -FilterScript { $_.Friendlyname -eq $CurrentBasePolicyName }).BasePolicyID
            $CurrentID = "{$CurrentID}"

            Write-Verbose -Message "This is the current ID of deployed base policy that is going to be used in the new base policy: $CurrentID"
            Write-Verbose -Message 'Reading the current base policy XML file'
            [System.Xml.XmlDocument]$Xml = Get-Content -Path '.\BasePolicy.xml'

            Write-Verbose -Message 'Setting the policy ID and Base policy ID to the current base policy ID in the generated XML file'
            $Xml.SiPolicy.PolicyID = $CurrentID
            $Xml.SiPolicy.BasePolicyID = $CurrentID

            Write-Verbose -Message 'Saving the updated XML file'
            $Xml.Save('.\BasePolicy.xml')

            Write-Verbose -Message 'Setting the policy version to 1.0.0.1'
            Set-CIPolicyVersion -FilePath .\BasePolicy.xml -Version '1.0.0.1'

            Write-Verbose -Message 'Setting HVCI to Strict'
            Set-HVCIOptions -Strict -FilePath .\BasePolicy.xml

            Write-Verbose -Message 'Converting the base policy to a CIP file'
            ConvertFrom-CIPolicy -XmlFilePath '.\BasePolicy.xml' -BinaryFilePath "$CurrentID.cip" | Out-Null

            $CurrentStep++
            Write-Progress -Id 12 -Activity 'Deploying the policy' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Deploying the new base policy with the same GUID on the system'
            &'C:\Windows\System32\CiTool.exe' --update-policy "$CurrentID.cip" -json | Out-Null

            $CurrentStep++
            Write-Progress -Id 12 -Activity 'Cleaning up' -Status "Step $CurrentStep/$TotalSteps" -PercentComplete ($CurrentStep / $TotalSteps * 100)

            Write-Verbose -Message 'Removing the base policy CIP file after deployment'
            Remove-Item -Path "$CurrentID.cip" -Force

            # Keep the new base policy XML file that was just deployed, in the current directory, so user can keep it for later
            # Defining a hashtable that contains the policy names and their corresponding XML file names
            [System.Collections.Hashtable]$PolicyFiles = @{
                'AllowMicrosoft_Plus_Block_Rules' = 'AllowMicrosoftPlusBlockRules.xml'
                'Lightly_Managed_system_Policy'   = 'SignedAndReputable.xml'
                'DefaultWindows_WithBlockRules'   = 'DefaultWindowsPlusBlockRules.xml'
            }

            Write-Verbose -Message 'Making sure a policy file with the same name as the current base policy does not exist in the current working directory'
            Remove-Item -Path $PolicyFiles[$NewBasePolicyType] -Force -ErrorAction SilentlyContinue

            Write-Verbose -Message 'Renaming the base policy XML file to match the new base policy type'
            Rename-Item -Path '.\BasePolicy.xml' -NewName $PolicyFiles[$NewBasePolicyType] -Force

            Write-ColorfulText -Color Pink -InputText "Base Policy has been successfully updated to $NewBasePolicyType"

            if (Get-CommonWDACConfig -UnsignedPolicyPath) {
                Write-Verbose -Message 'Replacing the old unsigned policy path in User Configurations with the new one'
                Set-CommonWDACConfig -UnsignedPolicyPath (Get-ChildItem -Path $PolicyFiles[$NewBasePolicyType]).FullName | Out-Null
            }
            Write-Progress -Id 12 -Activity 'Complete.' -Completed
        }
    }

    <#
.SYNOPSIS
    Edits Unsigned WDAC policies deployed on the system
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Edit-WDACConfig
.DESCRIPTION
    Using official Microsoft methods, Edits non-signed WDAC policies deployed on the system
.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module
.FUNCTIONALITY
    Using official Microsoft methods, Edits non-signed WDAC policies deployed on the system
.PARAMETER AllowNewApps
    While an unsigned WDAC policy is already deployed on the system, rebootlessly turn on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked.
.PARAMETER AllowNewAppsAuditEvents
    While an unsigned WDAC policy is already deployed on the system, rebootlessly turn on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked.
.PARAMETER MergeSupplementalPolicies
    Merges multiple deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one. System restart needed to take effect.
.PARAMETER UpdateBasePolicy
    It can rebootlessly change the type of the deployed base policy. It can update the recommended block rules and/or change policy rule options in the deployed base policy.
.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases
    It is used by the entire Cmdlet.
.PARAMETER Level
    The level that determines how the selected folder will be scanned.
    The default value for it is FilePublisher.
.PARAMETER Fallbacks
    The fallback level(s) that determine how the selected folder will be scanned.
    The default value for it is Hash.
.PARAMETER LogSize
    The log size to set for Code Integrity/Operational event logs
    The accepted values are between 1024 KB and 18014398509481983 KB
    The max range is the maximum allowed log size by Windows Event viewer
.INPUTS
    System.Int64
    System.String[]
    System.String
    System.Management.Automation.SwitchParameter
.OUTPUTS
    System.String
#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
Register-ArgumentCompleter -CommandName 'Edit-WDACConfig' -ParameterName 'PolicyPath' -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName 'Edit-WDACConfig' -ParameterName 'SuppPolicyPaths' -ScriptBlock $ArgumentCompleterPolicyPathsSupplementalPoliciesOnly

# SIG # Begin signature block
# MIILhgYJKoZIhvcNAQcCoIILdzCCC3MCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBgclqJ/HWFHD1V
# OZFUI6SVFqFgHsjsZ+9fskf9y4bYcqCCB88wggfLMIIFs6ADAgECAhNUAAAABzgp
# /t9ITGbLAAAAAAAHMA0GCSqGSIb3DQEBDQUAMEQxEzARBgoJkiaJk/IsZAEZFgNj
# b20xFDASBgoJkiaJk/IsZAEZFgRCaW5nMRcwFQYDVQQDEw5CaW5nLVNFUlZFUi1D
# QTAgFw0yMzEyMjcwODI4MDlaGA8yMTMzMTIyNzA4MzgwOVoweDELMAkGA1UEBhMC
# VUsxFjAUBgNVBAoTDVNweU5ldEdpcmwgQ28xKjAoBgNVBAMTIUhvdENha2VYIENv
# ZGUgU2lnbmluZyBDZXJ0aWZpY2F0ZTElMCMGCSqGSIb3DQEJARYWU3B5bmV0Z2ly
# bEBvdXRsb29rLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANsD
# szHV9Ea21AhOw4a35P1R30HHtmz+DlWKk/a4FvYQivl9dd+f+SZaybl0O96H6YNp
# qLnx7KD9TSEBbB+HxjE39GfWoX2R1VlPaDqkbGMA0XmnUB+/5CsbhktY4gbvJpW5
# LWXk0xUmCSvLMs7eiuBOGNs3zw5xVVNhsES6/aYMCWREI9YPTVbh7En6P4uZOisy
# K2tZtkSe/TXabfr1KtNhELr3DpTNtJBMBLzhz8d6ztJExKebFqpiaNqF7TpTOTRI
# 4P02k6u6lsWMz/rH9mMHdGSyBJ3DEyJGL9QT4jO4BFLHsxHuWTpjxnqxZNjwLTjB
# NEhH+VcKIIy2iWHfWwK2Nwr/3hzDbfqsWrMrXvvCqGpei+aZTxyplbMPpmd5myKo
# qLI58zc7cMi/HuAbbjo1YWxd/J1shHifMfhXfuncjHr7RTGC3BaEzwirQ12t1Z2K
# Zn2AhLnhSElbgZppt+WS4bmzT6L693srDxSMcBpRcu8NyDteLVCmgfBGXDdfAKEZ
# KXPi9liV0b66YQWnBp9/3bYwtYTh5VwjfSVAMfWsrMpIeGmvGUcsnQCqCxCulHKX
# onoYmbyotyOiXObXVgzB2G0k+VjxiFTSb1ENf3GJV1FJbzbch/p/tASY9w2L7kT/
# l+/Nnp4XOuPDYhm/0KWgEH7mUyq4KkP/BG/on7Q5AgMBAAGjggJ+MIICejA8Bgkr
# BgEEAYI3FQcELzAtBiUrBgEEAYI3FQjinCqC5rhWgdmZEIP42AqB4MldgT6G3Kk+
# mJFMAgFkAgEOMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBsGCSsGAQQBgjcVCgQOMAwwCgYIKwYBBQUHAwMwHQYDVR0O
# BBYEFFr7G/HfmP3Om/RStyhaEtEFmSYKMB8GA1UdEQQYMBaBFEhvdGNha2V4QG91
# dGxvb2suY29tMB8GA1UdIwQYMBaAFChQ2b1sdIHklqMDHsFKcUCX6YREMIHIBgNV
# HR8EgcAwgb0wgbqggbeggbSGgbFsZGFwOi8vL0NOPUJpbmctU0VSVkVSLUNBLENO
# PVNlcnZlcixDTj1DRFAsQ049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2Vy
# dmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1CaW5nLERDPWNvbT9jZXJ0aWZpY2F0
# ZVJldm9jYXRpb25MaXN0P2Jhc2U/b2JqZWN0Q2xhc3M9Y1JMRGlzdHJpYnV0aW9u
# UG9pbnQwgb0GCCsGAQUFBwEBBIGwMIGtMIGqBggrBgEFBQcwAoaBnWxkYXA6Ly8v
# Q049QmluZy1TRVJWRVItQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZp
# Y2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9QmluZyxEQz1jb20/
# Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRo
# b3JpdHkwDQYJKoZIhvcNAQENBQADggIBAE/AISQevRj/RFQdRbaA0Ffk3Ywg4Zui
# +OVuCHrswpja/4twBwz4M58aqBSoR/r9GZo69latO74VMmki83TX+Pzso3cG5vPD
# +NLxwAQUo9b81T08ZYYpdWKv7f+9Des4WbBaW9AGmX+jJn+JLAFp+8V+nBkN2rS9
# 47seK4lwtfs+rVMGBxquc786fXBAMRdk/+t8G58MZixX8MRggHhVeGc5ecCRTDhg
# nN68MhJjpwqsu0sY2NeKz5gMSk6wvt+NDPcfSZyNo1uSEMKTl/w5UH7mnrv0D4fZ
# UOY3cpIwbIagwdBuFupKG/m1I2LXZdLgGfOtZyZyw+c5Kd0KlMxonBiVoqN7PvoA
# 7sfwDI7PMLMQ3mseFbIpSUQGXHGeyouN1jF5ciySfHnW1goiG8tfDKNAT7WEz+ZT
# c1iIH+lCDUV/LmFD1Bvj2A9Q01C9BsScH+9vb2CnIwaSmfFRI6PY9cKOEHdy/ULi
# hp72QBd6W6ZQMZWXI5m48DdiKlQGA1aCdNN6+C0of43a7L0rAtLPYKySpd6gc34I
# h7/DgGLqXg0CO4KtbGdEWfKHqvh0qYLRmo/obhyVMYib4ceKrCcdc9aVlng/25nE
# ExvokF0vVXKSZkRUAfNHmmfP3lqbjABHC2slbStolocXwh8CoN8o2iOEMnY/xez0
# gxGYBY5UvhGKMYIDDTCCAwkCAQEwWzBEMRMwEQYKCZImiZPyLGQBGRYDY29tMRQw
# EgYKCZImiZPyLGQBGRYEQmluZzEXMBUGA1UEAxMOQmluZy1TRVJWRVItQ0ECE1QA
# AAAHOCn+30hMZssAAAAAAAcwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIB
# DDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEE
# AYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgbsbb631Qnp/a
# kDzL8zDIwvnJF1/+QY392ZOm1GUBg5IwDQYJKoZIhvcNAQEBBQAEggIA2uwXolpA
# ELjb5MJFLimClFwnWNIkPdMJKzaO8+jVhlg+HOn2pPWp6igs2uxnybleWkFGyayq
# 2TwJsVJnO40iYVhuzoTkueaOYaNbeTOBmD1Uj7h0kbvN94qRxN7pwBkTpTejlQ1/
# rFB6BETCJewrsRPdk6/0+fXc+5KRmI7M8TZhjioS9RLrF9Jl2weZDvyOfaofDihy
# O0vYbIWZkmfKdGEpFXYQhZilacW/4kJM75LwTLjNIg6mCxzY5aJYWciBN4mOcDiQ
# r3Y/Jj8emZmOl7+iFjmuRHNy/ebblLWIZkigJzSlppvMCxTewz0gJHHSl4VfCAfr
# icQuNUGij0ToBcEpgLL6cMfXNvYOkU92YUyYo6RJ25c//3k4LIokKVVizJqjO4PZ
# h4cWN7HAXRs4X2vTVBBrO2SY05y3nX4yPzZpbwpXPUQpvMliXjdoZ80cY5A20+yg
# 60lf/YePFiLiGMgautaIvwMu+0hgltqcf03jt/cSiGcPoWaGuz1LvBYttdAYhw/d
# UVocr4zgXAqs7DV04aY93wuyPpkb8llyV5qVe0B/cR7iotCav1ZUUoFwbjfOrtcP
# qToG5e1+CH7UgS2g3c56Gj4LPH3NPmQCJSHSTjbnVNx4LBFChMe2KDPF9LtZY4DO
# Qap1RXlBl2sil1/Ax887FccdIgXvtriyX/4=
# SIG # End signature block
