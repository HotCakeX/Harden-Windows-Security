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

        [ValidateCount(1, 232)]
        [ValidatePattern('^[a-zA-Z0-9 \-]+$', ErrorMessage = 'The policy name can only contain alphanumeric, space and dash (-) characters.')]
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
                    Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -NoNewWindow
                    Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -NoNewWindow
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
.PARAMETER SuppPolicyName
    The name of the Supplemental policy that will be created
.PARAMETER PolicyPath
    The path to the base policy XML file that will be used
.PARAMETER SuppPolicyPaths
    The path(s) to the Supplemental policy XML file(s) that will be used
.PARAMETER KeepOldSupplementalPolicies
    Keep the old Supplemental policies that are going to be merged into a single policy
.PARAMETER NoScript
    If specified, scripts will not be scanned
.PARAMETER NoUserPEs
    If specified, user mode binaries will not be scanned
.PARAMETER SpecificFileNameLevel
    The more specific level that determines how the selected file will be scanned.
.PARAMETER IncludeDeletedFiles
    If specified, deleted files will be included in the scan
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
# MIILkgYJKoZIhvcNAQcCoIILgzCCC38CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBcvekjAeWPx0iO
# RZJAoBdqSKmkB5G0ELepP8yCmFvYq6CCB9AwggfMMIIFtKADAgECAhMeAAAABI80
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
# IgQgHQqLaeBc38cNKApuwXYWbwOVhNjKLk/2rBa8D9ZqlDcwDQYJKoZIhvcNAQEB
# BQAEggIAXI0RpuGm0dnTDttFPTUwqpabZXa7KLzwEYM8M65D+zIp5EFMQgAkigZx
# i+qiubz+PDNzQXy9rSUEuLaXKOGgUvbah/cJTSgcZ/Q5VAlX3e2EZVDPFj5QYsDm
# XFCxedbHoIbavHArFhTnRenz1IqLkfk3wDHWykORyVVo0ECSre3xRzYy4ylzLOW+
# ukMXP6O2Qyyy+Y8UvS+FKp0D+bQ2PssoJIje7cJoC1+OfsHXRgDkWHuIfeOSCer/
# n4loyEPJomZgHiyH53W7twNZewlqkbuweCZZ3PL9aiCneuU/xo8kSeaPeSWnbARW
# zN+dUpLJhS1N6gWeSuehKNhaZm9w7nzLmPvwc8Wf1dweUM9i/OADkuHjj56WcAcO
# fpxNUMcZABHJygKmyuYTTASTXUon/2v6kITnQMkQzPGmSSaHh5fr4YuydNjlIp6X
# ZAYo+3FOPKFoXCdnsJCb4rm7cxI4G2AOo7W9m6XP/hMA29sDsWmw9JgViVmQb52U
# /JcyxW71LntShTCfWFcW+x/gcIcMuYcHLDuU3rfmqNTJaLbMnx5ApX5D63VsIYq7
# f51wII5pYz/T/aQkoCOVNkBPk7I2ktTt8KTCSi9F6DbvNhi6v6Kz46bIUFrCpaOP
# ZShiBw+AdStCfBpWbYRWbrbMMfvfqY4U2V6hLGq7GgBuEqdVoiQ=
# SIG # End signature block
