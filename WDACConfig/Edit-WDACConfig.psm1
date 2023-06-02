#Requires -RunAsAdministrator
function Edit-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = "Allow New Apps Audit Events",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Alias("E")]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")][Switch]$AllowNewAppsAuditEvents,
        [Alias("A")]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")][Switch]$AllowNewApps,
        [Alias("M")]
        [Parameter(Mandatory = $false, ParameterSetName = "Merge Supplemental Policies")][Switch]$MergeSupplementalPolicies,
        [Alias("U")]
        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy")][Switch]$UpdateBasePolicy,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = "The Supplemental Policy Name can only contain alphanumeric and space characters.")]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [System.String]$SuppPolicyName,
        
        [ValidatePattern('\.xml$')]
        [ValidateScript({
                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to
                # Edit a Signed policy using Edit-WDACConfig cmdlet which is only made for Unsigned policies
                $_ | ForEach-Object {                   
                    $xmlTest = [xml](Get-Content $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    $RedFlag3 = $xmlTest.SiPolicy.PolicyID
                    $CurrentPolicyIDs = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).policyID | ForEach-Object { "{$_}" }
                    if (!$RedFlag1 -and !$RedFlag2) {
                        if ($CurrentPolicyIDs -contains $RedFlag3) {
                            return $True 
                        }
                        else { throw "The currently selected policy xml file isn't deployed." }
                    }
                    # This throw is shown only when User added a Signed policy xml file for Unsigned policy file path property in user configuration file
                    # Without this, the error shown would be vague: The variable cannot be validated because the value System.String[] is not a valid value for the PolicyPaths variable.
                    else { throw "The policy xml file in User Configurations for UnsignedPolicyPath is a Signed policy." }                        
                }
            }, ErrorMessage = "The selected policy xml file is Signed. Please use Edit-SignedWDACConfig cmdlet to edit Signed policies.")]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$PolicyPaths,

        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = "The path you selected is not a file path.")]      
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = "Merge Supplemental Policies")]
        [switch]$KeepOldSupplementalPolicies,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [System.String]$Level = "FilePublisher", # Setting the default value for the Level parameter

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [System.String[]]$Fallbacks = "Hash", # Setting the default value for the Fallbacks parameter

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [Switch]$NoScript,

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [Switch]$NoUserPEs,

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [Switch]$AllowFileNameFallbacks,
        
        [ValidateSet("OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [System.String]$SpecificFileNameLevel,

        # Setting the maxim range to the maximum allowed log size by Windows Event viewer
        [ValidateRange(1024KB, 18014398509481983KB)]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [System.Int64]$LogSize,

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")][Switch]$IncludeDeletedFiles,

        [ValidateSet([BasePolicyNamez])]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")][System.String[]]$CurrentBasePolicyName,

        [ValidateSet("AllowMicrosoft_Plus_Block_Rules", "Lightly_Managed_system_Policy", "DefaultWindows_WithBlockRules")]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")][System.String]$NewBasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy")][Switch]$RequireEVSigners,

        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { . Update-self } 

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent

        #region User-Configurations-Processing-Validation
        # make sure the ParameterSet being used has PolicyPaths parameter - Then enforces "mandatory" attribute for the parameter          
        if ($PSCmdlet.ParameterSetName -in "Allow New Apps Audit Events", "Allow New Apps", "Merge Supplemental Policies") {
            # If any of these parameters, that are mandatory for all of the position 0 parameters, isn't supplied by user
            if (!$PolicyPaths) {
                # Read User configuration file if it exists
                $UserConfig = Get-Content -Path "$env:USERPROFILE\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue   
                if ($UserConfig) {
                    # Validate the Json file and read its content to make sure it's not corrupted
                    try { $UserConfig = $UserConfig | ConvertFrom-Json }
                    catch {            
                        Write-Error "User Configuration Json file is corrupted, deleting it..." -ErrorAction Continue
                        # Calling this function with this parameter automatically does its job and breaks/stops the operation
                        Set-CommonWDACConfig -DeleteUserConfig         
                    }                
                }
            }
            # If PolicyPaths has no values
            if (!$PolicyPaths) {            
                if ($UserConfig.UnsignedPolicyPath) {
                    # validate each policyPath read from user config file
                    if (Test-Path $($UserConfig.UnsignedPolicyPath)) {
                        $PolicyPaths = $UserConfig.UnsignedPolicyPath
                    }
                    else {
                        throw "The currently saved value for UnsignedPolicyPath in user configurations is invalid."
                    }           
                }
                else {
                    throw "PolicyPaths parameter can't be empty and no valid configuration was found for UnsignedPolicyPath."
                }
            }
        }        
        #endregion User-Configurations-Processing-Validation

        # argument tab auto-completion and ValidateSet for Policy names 
        Class BasePolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $BasePolicyNamez = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.PolicyID -eq $_.BasePolicyID }).Friendlyname
           
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

        # Redeploy the base policy in Enforced mode
        function Update-BasePolicyToEnforced {
            # Deploy Enforced mode CIP            
            CiTool --update-policy ".\$PolicyID.cip" -json | Out-Null         
            &$WriteTeaGreen "`nThe Base policy with the following details has been Re-Deployed in Enforced Mode:"       
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID"
            # Remove Enforced Mode CIP
            Remove-Item ".\$PolicyID.cip" -Force
        }       

        $DriveLettersGlobalRootFix = Invoke-Command -ScriptBlock $DriveLettersGlobalRootFixScriptBlock
    }

    process {        

        if ($AllowNewApps) {
            # remove any possible files from previous runs
            Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path ".\SupplementalPolicy$SuppPolicyName.xml" -Force -ErrorAction SilentlyContinue    
            # An empty array that holds the Policy XML files - This array will eventually be used to create the final Supplemental policy
            $PolicyXMLFilesArray = @()
    
            #Initiate Live Audit Mode

            foreach ($PolicyPath in $PolicyPaths) {                
                # Creating a copy of the original policy in Temp folder so that the original one will be unaffected
                $PolicyFileName = Split-Path $PolicyPath -Leaf
                Remove-Item -Path "$env:Temp\$PolicyFileName" -Force -ErrorAction SilentlyContinue # make sure no file with the same name already exists in Temp folder         
                Copy-Item -Path $PolicyPath -Destination $env:Temp -Force                
                $PolicyPath = "$env:Temp\$PolicyFileName"

                # defining Base policy
                $xml = [xml](Get-Content $PolicyPath)            
                $PolicyID = $xml.SiPolicy.PolicyID
                $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object { $_.provider -eq "PolicyInfo" -and $_.valuename -eq "Name" -and $_.key -eq "Information" }).value.string
    
                # Remove any cip file if there is any
                Remove-Item -Path ".\*.cip" -Force -ErrorAction SilentlyContinue

                # Create CIP for Audit Mode
                Set-RuleOption -FilePath $PolicyPath -Option 3 # Add Audit mode policy rule option
                ConvertFrom-CIPolicy $PolicyPath ".\AuditMode.cip" | Out-Null
                
                # Create CIP for Enforced Mode
                Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete # Remove Audit mode policy rule option
                ConvertFrom-CIPolicy $PolicyPath ".\EnforcedMode.cip" | Out-Null               

                ################# Snap back guarantee #################
                Write-Debug -Message "Creating Enforced Mode SnapBack guarantee"

                <#
                # CMD and Scheduled Task Method                
                $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c c:\EnforcedModeSnapBack.cmd'
                $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
                $principal = New-ScheduledTaskPrincipal -GroupId 'BUILTIN\Administrators' -RunLevel Highest
                $TaskSettings = New-ScheduledTaskSettingsSet -Hidden -Compatibility Win8 -DontStopIfGoingOnBatteries -Priority 0 -AllowStartIfOnBatteries
                Register-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Action $taskAction -Trigger $taskTrigger -Principal $principal -Settings $TaskSettings -Force | Out-Null
                 
                Set-Content -Force "c:\EnforcedModeSnapBack.cmd" -Value @"
REM Deploying the Enforced Mode SnapBack CI Policy
CiTool --update-policy "$((Get-Location).Path)\$PolicyID.cip" -json
REM Deleting the Scheduled task responsible for running this CMD file
schtasks /Delete /TN EnforcedModeSnapBack /F
REM Deleting the CI Policy file
del /f /q "$((Get-Location).Path)\$PolicyID.cip"
REM Deleting this CMD file itself
del "%~f0"
"@          
#>
                # PowerShell and RunOnce Method
                
                $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                $command = @"
CiTool --update-policy "$((Get-Location).Path)\$PolicyID.cip" -json; Remove-Item -Path "$((Get-Location).Path)\$PolicyID.cip" -Force
"@
                $command | Out-File "C:\EnforcedModeSnapBack.ps1"
                New-ItemProperty -Path $registryPath -Name '*CIPolicySnapBack' -Value "powershell.exe -WindowStyle `"Hidden`" -ExecutionPolicy `"Bypass`" -Command `"& {&`"C:\EnforcedModeSnapBack.ps1`";Remove-Item -Path 'C:\EnforcedModeSnapBack.ps1' -Force}`"" -PropertyType String | Out-Null
                          
                # Deploy Audit mode CIP
                Write-Debug -Message "Deploying Audit mode CIP"
                Rename-Item ".\AuditMode.cip" -NewName ".\$PolicyID.cip" -Force
                CiTool --update-policy ".\$PolicyID.cip" -json | Out-Null         
                &$WriteTeaGreen "`nThe Base policy with the following details has been Re-Deployed in Audit Mode:"      
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID"
                # Remove Audit Mode CIP
                Remove-Item ".\$PolicyID.cip" -Force
                # Prepare Enforced Mode CIP for Deployment - waiting to be Re-deployed at the right time
                Rename-Item ".\EnforcedMode.cip" -NewName ".\$PolicyID.cip" -Force     
                
                # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode                
                Try {
                    ################################### User Interaction ####################################            
                    &$WritePink "`nAudit mode deployed, start installing your programs now"
                    &$WriteViolet "When you've finished installing programs, Press Enter to start selecting program directories to scan`n"
                    Pause

                    # Store the program paths that user browses for in an array
                    $ProgramsPaths = @()
                    Write-host "`nSelect program directories to scan" -ForegroundColor Cyan
                    # Showing folder picker GUI to the user for folder path selection
                    do {
                        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                        $OBJ = New-Object System.Windows.Forms.FolderBrowserDialog
                        $OBJ.InitialDirectory = "$env:SystemDrive"
                        $OBJ.Description = $Description
                        $Spawn = New-Object System.Windows.Forms.Form -Property @{TopMost = $true }
                        $Show = $OBJ.ShowDialog($Spawn)
                        If ($Show -eq "OK") { $ProgramsPaths += $OBJ.SelectedPath }
                        Else { break }
                    }
                    while ($true)

                    # Make sure User browsed for at least 1 directory
                    # Exit the operation if user didn't select any folder paths
                    if ($ProgramsPaths.count -eq 0) {                                      
                        Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Red
                        # Causing break here to stop operation. Finally block will be triggered to Re-Deploy Base policy in Enforced mode
                        break
                    }
                }
                catch {
                    # Show any extra info about any possible error that might've occured                   
                    $_
                    $_.CategoryInfo
                    $_.ErrorDetails
                    $_.Exception
                    $_.FullyQualifiedErrorId
                    $_.InvocationInfo
                    $_.PipelineIterationInfo
                    $_.PSMessageDetails
                    $_.ScriptStackTrace
                    $_.TargetObject
                }
                finally {                                          
                    # Deploy Enforced mode CIP
                    Write-Debug -Message "Finally Block Running"
                    Update-BasePolicyToEnforced                                        
                    
                    # Enforced Mode Snapback removal after base policy has already been successfully re-enforced
                    Write-Debug -Message "Removing the SnapBack guarantee because the base policy has been successfully re-enforced"
                    
                    # For PowerShell Method
                    Remove-Item -Path "C:\EnforcedModeSnapBack.ps1" -Force                     
                    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*CIPolicySnapBack" -Force
                                        
                    # For CMD Method
                    # Unregister-ScheduledTask -TaskName 'EnforcedModeSnapBack' -Confirm:$false
                    # Remove-Item -Path 'c:\EnforcedModeSnapBack.cmd' -Force                
                }
                
                Write-Host "`nHere are the paths you selected:" -ForegroundColor Yellow
                $ProgramsPaths | ForEach-Object { $_ }
    
                #Process Program Folders From User input                    
          
                # Scan each of the folder paths that user selected
                for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                    # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                    [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                        FilePath             = ".\ProgramDir_ScanResults$($i).xml"
                        ScanPath             = $ProgramsPaths[$i]
                        Level                = $Level
                        Fallback             = $Fallbacks
                        MultiplePolicyFormat = $true
                        UserWriteablePaths   = $true
                    }
                    # Assess user input parameters and add the required parameters to the hash table
                    if ($AllowFileNameFallbacks) { $UserInputProgramFoldersPolicyMakerHashTable['AllowFileNameFallbacks'] = $true }
                    if ($SpecificFileNameLevel) { $UserInputProgramFoldersPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                    if ($NoScript) { $UserInputProgramFoldersPolicyMakerHashTable['NoScript'] = $true }                      
                    if (!$NoUserPEs) { $UserInputProgramFoldersPolicyMakerHashTable['UserPEs'] = $true } 

                    # Create the supplemental policy via parameter splatting
                    New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable
                }            
    
                # merge-cipolicy accept arrays - collecting all the policy files created by scanning user specified folders
                $ProgramDir_ScanResults = Get-ChildItem ".\" | Where-Object { $_.Name -like 'ProgramDir_ScanResults*.xml' }                
                foreach ($file in $ProgramDir_ScanResults) {
                    $PolicyXMLFilesArray += $file.FullName
                }
    
                Write-Debug -Message "The following policy xml files are going to be merged into the final Supplemental policy and be deployed on the system:"
                if ($Debug) { $PolicyXMLFilesArray | ForEach-Object { Write-Debug -Message "$_" } }
                    
                # Merge all of the policy XML files in the array into the final Supplemental policy
                Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\SupplementalPolicy$SuppPolicyName.xml" | Out-Null                                  
       
                Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force
                
                #################### Supplemental-policy-processing-and-deployment ############################
        
                $SuppPolicyPath = ".\SupplementalPolicy$SuppPolicyName.xml" 
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "Supplemental Policy $SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)                
    
                # Make sure policy rule options that don't belong to a Supplemental policy don't exit
                @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }
     
                Set-HVCIOptions -Strict -FilePath $SuppPolicyPath             
                Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version "1.0.0.0"            

                ConvertFrom-CIPolicy $SuppPolicyPath "$SuppPolicyID.cip" | Out-Null 
                CiTool --update-policy ".\$SuppPolicyID.cip" -json | Out-Null
                &$WriteTeaGreen "`nSupplemental policy with the following details has been Deployed in Enforced Mode:"
                Write-Output "SupplementalPolicyName = $SuppPolicyName"
                Write-Output "SupplementalPolicyGUID = $SuppPolicyID"
                Remove-Item ".\$SuppPolicyID.cip" -Force
                Remove-Item -Path $PolicyPath -Force # Remove the policy xml file in Temp folder we created earlier   
            }
        }

        if ($AllowNewAppsAuditEvents) {
            # Change Code Integrity event logs size
            if ($AllowNewAppsAuditEvents -and $LogSize) { Set-LogSize -LogSize $LogSize }
            # Make sure there is no leftover from previous runs
            Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path ".\SupplementalPolicy$SuppPolicyName.xml" -Force -ErrorAction SilentlyContinue
            # Get the current date so that instead of the entire event viewer logs, only audit logs created after running this module will be captured
            # The notice about variable being assigned and never used should be ignored - it's being dot-sourced from Resources file
            $Date = Get-Date
            # An empty array that holds the Policy XML files - This array will eventually be used to create the final Supplemental policy
            $PolicyXMLFilesArray = @()

            ################################### Initiate Live Audit Mode ###################################
            
            foreach ($PolicyPath in $PolicyPaths) {                
                # Creating a copy of the original policy in Temp folder so that the original one will be unaffected
                $PolicyFileName = Split-Path $PolicyPath -Leaf
                Remove-Item -Path "$env:Temp\$PolicyFileName" -Force -ErrorAction SilentlyContinue # make sure no file with the same name already exists in Temp folder         
                Copy-Item -Path $PolicyPath -Destination $env:Temp -Force                
                $PolicyPath = "$env:Temp\$PolicyFileName"
                                
                # Defining Base policy
                $xml = [xml](Get-Content $PolicyPath)            
                $PolicyID = $xml.SiPolicy.PolicyID
                $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object { $_.provider -eq "PolicyInfo" -and $_.valuename -eq "Name" -and $_.key -eq "Information" }).value.string

                # Remove any cip file if there is any
                Remove-Item -Path ".\*.cip" -Force -ErrorAction SilentlyContinue                

                # Create CIP for Audit Mode
                Set-RuleOption -FilePath $PolicyPath -Option 3 # Add Audit mode policy rule option
                ConvertFrom-CIPolicy $PolicyPath ".\AuditMode.cip" | Out-Null
                 
                # Create CIP for Enforced Mode
                Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete # Remove Audit mode policy rule option
                ConvertFrom-CIPolicy $PolicyPath ".\EnforcedMode.cip" | Out-Null
                             
                ################# Snap back guarantee #################
                Write-Debug -Message "Creating Enforced Mode SnapBack guarantee"
               
                $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                $command = @"
CiTool --update-policy "$((Get-Location).Path)\$PolicyID.cip" -json; Remove-Item -Path "$((Get-Location).Path)\$PolicyID.cip" -Force
"@
                $command | Out-File "C:\EnforcedModeSnapBack.ps1"
                New-ItemProperty -Path $registryPath -Name '*CIPolicySnapBack' -Value "powershell.exe -WindowStyle `"Hidden`" -ExecutionPolicy `"Bypass`" -Command `"& {&`"C:\EnforcedModeSnapBack.ps1`";Remove-Item -Path 'C:\EnforcedModeSnapBack.ps1' -Force}`"" -PropertyType String | Out-Null

                # Deploy Audit mode CIP
                Write-Debug -Message "Deploying Audit mode CIP"
                Rename-Item ".\AuditMode.cip" -NewName ".\$PolicyID.cip" -Force
                CiTool --update-policy ".\$PolicyID.cip" -json | Out-Null         
                &$WriteTeaGreen "`nThe Base policy with the following details has been Re-Deployed in Audit Mode:"      
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID"
                # Remove Audit Mode CIP
                Remove-Item ".\$PolicyID.cip" -Force
                # Prepare Enforced Mode CIP for Deployment - waiting to be Re-deployed at the right time
                Rename-Item ".\EnforcedMode.cip" -NewName ".\$PolicyID.cip" -Force

                # A Try-Catch-Finally block so that if any errors occur, the Base policy will be Re-deployed in enforced mode                
                Try {
                    ################################### User Interaction ####################################
                    &$WritePink "`nAudit mode deployed, start installing your programs now"
                    &$WriteViolet "When you've finished installing programs, Press Enter to start selecting program directories to scan`n"
                    Pause                 

                    # Store the program paths that user browses for in an array
                    $ProgramsPaths = @()
                    Write-host "`nSelect program directories to scan`n" -ForegroundColor Cyan
                    # Showing folder picker GUI to the user for folder path selection
                    do {
                        [System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms") | Out-Null
                        $OBJ = New-Object System.Windows.Forms.FolderBrowserDialog
                        $OBJ.InitialDirectory = "$env:SystemDrive"
                        $OBJ.Description = $Description
                        $Spawn = New-Object System.Windows.Forms.Form -Property @{TopMost = $true }
                        $Show = $OBJ.ShowDialog($Spawn)
                        If ($Show -eq "OK") { $ProgramsPaths += $OBJ.SelectedPath }
                        Else { break }
                    }
                    while ($true)
                
                    # Make sure User browsed for at least 1 directory
                    # Exit the operation if user didn't select any folder paths
                    if ($ProgramsPaths.count -eq 0) {                                      
                        Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Red
                        # Causing break here to stop operation. Finally block will be triggered to Re-Deploy Base policy in Enforced mode
                        break
                    }
                    
                    Write-Host "Here are the paths you selected:" -ForegroundColor Yellow
                    $ProgramsPaths | ForEach-Object { $_ }

                    ################################### EventCapturing ################################

                    Write-host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan    

                    # Extracting the array content from Get-AuditEventLogsProcessing function
                    $AuditEventLogsProcessingResults = Get-AuditEventLogsProcessing -Date $Date

                    # Only create policy for files that are available on the disk based on Event viewer logs but weren't in user-selected program path(s), if there are any
                    if ($AuditEventLogsProcessingResults.AvailableFilesPaths) {

                        # Using the function to find out which files are not in the user-selected path(s), if any, to only scan those
                        # this prevents duplicate rule creation and double file copying
                        $TestFilePathResults = (Test-FilePath -FilePath $AuditEventLogsProcessingResults.AvailableFilesPaths -DirectoryPath $ProgramsPaths).path | Select-Object -Unique
                        
                        Write-Debug -Message "$($TestFilePathResults.count) file(s) have been found in event viewer logs that don't exist in any of the folder paths you selected."

                        # Another check to make sure there were indeed files found in Event viewer logs but weren't in any of the user-selected path(s)
                        if ($TestFilePathResults) {
                            # Create a folder in Temp directory to copy the files that are not included in user-selected program path(s)
                            # but detected in Event viewer audit logs, scan that folder, and in the end delete it                   
                            New-Item -Path "$env:TEMP\TemporaryScanFolderForEventViewerFiles" -ItemType Directory | Out-Null
                            
                            Write-Debug -Message "The following file(s) are being copied to the TEMP directory for scanning because they were found in event logs but didn't exist in any of the user-selected paths:"      
                            $TestFilePathResults | ForEach-Object {
                                Write-Debug -Message "$_"    
                                Copy-Item -Path $_ -Destination "$env:TEMP\TemporaryScanFolderForEventViewerFiles\" -ErrorAction SilentlyContinue
                            }
                      
                            # Create a policy XML file for available files on the disk

                            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                            [System.Collections.Hashtable]$AvailableFilesOnDiskPolicyMakerHashTable = @{
                                FilePath             = ".\RulesForFilesNotInUserSelectedPaths.xml"
                                ScanPath             = "$env:TEMP\TemporaryScanFolderForEventViewerFiles\"
                                Level                = $Level
                                Fallback             = $Fallbacks
                                MultiplePolicyFormat = $true
                                UserWriteablePaths   = $true                            
                            }
                            # Assess user input parameters and add the required parameters to the hash table
                            if ($AllowFileNameFallbacks) { $AvailableFilesOnDiskPolicyMakerHashTable['AllowFileNameFallbacks'] = $true }
                            if ($SpecificFileNameLevel) { $AvailableFilesOnDiskPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                            if ($NoScript) { $AvailableFilesOnDiskPolicyMakerHashTable['NoScript'] = $true }
                            if (!$NoUserPEs) { $AvailableFilesOnDiskPolicyMakerHashTable['UserPEs'] = $true } 
                        
                            # Create the supplemental policy via parameter splatting
                            New-CIPolicy @AvailableFilesOnDiskPolicyMakerHashTable
                        
                            # Add the policy XML file to the array that holds policy XML files
                            $PolicyXMLFilesArray += ".\RulesForFilesNotInUserSelectedPaths.xml"
                            # Delete the Temporary folder in the TEMP folder
                            Remove-Item -Recurse -Path "$env:TEMP\TemporaryScanFolderForEventViewerFiles\" -Force
                        }
                    }
                                    
                    # Only create policy for files that are on longer available on the disk if there are any and
                    # if user chose to include deleted files in the final supplemental policy
                    if ($AuditEventLogsProcessingResults.DeletedFileHashes -and $IncludeDeletedFiles) {

                        Write-Debug -Message "$($AuditEventLogsProcessingResults.DeletedFileHashes.count) file(s) have been found in event viewer logs that were run during Audit phase but are no longer on the disk, they are as follows:"
                        $AuditEventLogsProcessingResults.DeletedFileHashes | ForEach-Object {
                            Write-Debug -Message "$($_.'File Name')"
                        }
                       
                        # Save the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the current working directory for debugging purposes               
                        ((Get-FileRules -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes) + (Get-RuleRefs -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes)).Trim() | Out-File FileRulesAndFileRefs.txt

                        # Put the Rules and RulesRefs in an empty policy file                
                        New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes) -RuleRefsContent (Get-RuleRefs -HashesArray $AuditEventLogsProcessingResults.DeletedFileHashes) | Out-File .\DeletedFileHashesEventsPolicy.xml
                
                        # adding the policy file that consists of rules from audit even logs, to the array
                        $PolicyXMLFilesArray += ".\DeletedFileHashesEventsPolicy.xml"
                    }
                                      
                    ######################## Process Program Folders From User input #####################
                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                            FilePath             = ".\ProgramDir_ScanResults$($i).xml"
                            ScanPath             = $ProgramsPaths[$i]
                            Level                = $Level
                            Fallback             = $Fallbacks
                            MultiplePolicyFormat = $true
                            UserWriteablePaths   = $true
                        }
                        # Assess user input parameters and add the required parameters to the hash table
                        if ($AllowFileNameFallbacks) { $UserInputProgramFoldersPolicyMakerHashTable['AllowFileNameFallbacks'] = $true }
                        if ($SpecificFileNameLevel) { $UserInputProgramFoldersPolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
                        if ($NoScript) { $UserInputProgramFoldersPolicyMakerHashTable['NoScript'] = $true }                      
                        if (!$NoUserPEs) { $UserInputProgramFoldersPolicyMakerHashTable['UserPEs'] = $true } 

                        # Create the supplemental policy via parameter splatting
                        New-CIPolicy @UserInputProgramFoldersPolicyMakerHashTable
                    }            

                    # Merge-cipolicy accept arrays - collecting all the policy files created by scanning user specified folders
                    $ProgramDir_ScanResults = Get-ChildItem ".\" | Where-Object { $_.Name -like 'ProgramDir_ScanResults*.xml' }                
                    foreach ($file in $ProgramDir_ScanResults) {
                        $PolicyXMLFilesArray += $file.FullName
                    }
                    
                    #region Kernel-protected-files-automatic-detection-and-allow-rule-creation                    
                    # This part takes care of Kernel protected files such as the main executable of the games installed through Xbox app
                    # For these files, only Kernel can get their hashes, it passes them to event viewer and we take them from event viewer logs
                    # Any other attempts such as "Get-FileHash" or "Get-AuthenticodeSignature" fail and ConfigCI Module cmdlets totally ignore these files and do not create allow rules for them

                    # Finding the file(s) first and storing them in an array
                    $ExesWithNoHash = @()
                    # looping through each user-selected path(s)
                    foreach ($ProgramsPath in $ProgramsPaths) {
                        # Making sure the currently processing path has any .exe in it
                        $AnyAvailableExes = (Get-ChildItem -Recurse -Path $ProgramsPath -Filter "*.exe").FullName
                        # if any .exe was found then continue testing them
                        if ($AnyAvailableExes) {
                            $AnyAvailableExes | ForEach-Object {
                                $CurrentExeWithNoHash = $_
                                try {
                                    # Testing each executable to find the protected ones
                                    Get-FileHash -Path $CurrentExeWithNoHash -ErrorAction Stop | Out-Null
                                }
                                # Making sure only the right file is captured by narrowing down the error type.   
                                # E.g., when get-filehash can't get a file's hash because its open by another program, the exception is different: System.IO.IOException        
                                catch [System.UnauthorizedAccessException] {            
                                    $ExesWithNoHash += $CurrentExeWithNoHash
                                } 
                            }
                        }
                    }
                    # Only proceed if any kernel protected file(s) were found in any of the user-selected directory path(s)
                    if ($ExesWithNoHash) {

                        Write-Debug -Message "The following Kernel protected files detected, creating allow rules for them:`n"
                        if ($Debug) { $ExesWithNoHash | ForEach-Object { Write-Debug -Message "$_" } }
                                                         
                        $KernelProtectedHashesBlock = {
                            foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $Date } ) {
                                $xml = [xml]$event.toxml()
                                $xml.event.eventdata.data |
                                ForEach-Object { $hash = @{} } { $hash[$_.name] = $_.'#text' } { [pscustomobject]$hash } |
                                ForEach-Object {
                                    if ($_.'File Name' -match ($pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$')) {
                                        $hardDiskVolumeNumber = $Matches[1]
                                        $remainingPath = $Matches[2]
                                        $getletter = $DriveLettersGlobalRootFix | Where-Object { $_.devicepath -eq "\Device\HarddiskVolume$hardDiskVolumeNumber" }
                                        $usablePath = "$($getletter.DriveLetter)$remainingPath"
                                        $_.'File Name' = $_.'File Name' -replace $pattern, $usablePath
                                    } # Check if file is currently on the disk
                                    if (Test-Path $_.'File Name') {
                                        # Check if the file exits in the $ExesWithNoHash array
                                        if ($ExesWithNoHash -contains $_.'File Name') {
                                            $_ | Select-Object FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
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
                            (Get-FileRules -HashesArray $KernelProtectedHashesBlockResults) + (Get-RuleRefs -HashesArray $KernelProtectedHashesBlockResults) | Out-File KernelProtectedFiles.txt

                            # Put the Rules and RulesRefs in an empty policy file                
                            New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $KernelProtectedHashesBlockResults) -RuleRefsContent (Get-RuleRefs -HashesArray $KernelProtectedHashesBlockResults) | Out-File .\KernelProtectedFiles.xml

                            # adding the policy file  to the array of xml files
                            $PolicyXMLFilesArray += ".\KernelProtectedFiles.xml"
                        }
                        else {
                            Write-Warning -Message "The following Kernel protected files detected, but no hash was found for them in Event viewer logs.`nThis means you didn't run those files/programs when Audit mode was turned on.`n"
                            $ExesWithNoHash | ForEach-Object { Write-Warning -Message "$_" }
                        }
                    }                    
                    #endregion Kernel-protected-files-automatic-detection-and-allow-rule-creation

                    Write-Debug -Message "The following policy xml files are going to be merged into the final Supplemental policy and be deployed on the system:"
                    if ($Debug) { $PolicyXMLFilesArray | ForEach-Object { Write-Debug -Message "$_" } }

                    # Merge all of the policy XML files in the array into the final Supplemental policy
                    Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\SupplementalPolicy$SuppPolicyName.xml" | Out-Null     

                    # Delete these extra files unless user uses -Debug parameter
                    if (-NOT $Debug) {
                        Remove-Item -Path ".\RulesForFilesNotInUserSelectedPaths.xml", ".\ProgramDir_ScanResults*.xml" -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path ".\KernelProtectedFiles.xml", ".\DeletedFileHashesEventsPolicy.xml" -Force -ErrorAction SilentlyContinue
                        Remove-Item -Path ".\KernelProtectedFiles.txt", ".\FileRulesAndFileRefs.txt" -Force -ErrorAction SilentlyContinue
                    }
                }
                # Unlike AllowNewApps parameter, AllowNewAppsAuditEvents parameter performs Event viewer scanning and kernel protected files detection
                # So the base policy enforced mode snap back can't happen any sooner than this point
                catch {                    
                    $_
                    $_.CategoryInfo
                    $_.ErrorDetails
                    $_.Exception
                    $_.FullyQualifiedErrorId
                    $_.InvocationInfo
                    $_.PipelineIterationInfo
                    $_.PSMessageDetails
                    $_.ScriptStackTrace
                    $_.TargetObject
                }
                finally {                                          
                    # Deploy Enforced mode CIP
                    Write-Debug -Message "Finally Block Running"
                    Update-BasePolicyToEnforced                    
                    # Enforced Mode Snapback removal after base policy has already been successfully re-enforced
                    Write-Debug -Message "Removing the SnapBack guarantee because the base policy has been successfully re-enforced"
                    Remove-Item -Path "C:\EnforcedModeSnapBack.ps1" -Force                     
                    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "*CIPolicySnapBack" -Force                                        
                }

                #################### Supplemental-policy-processing-and-deployment ############################

                $SuppPolicyPath = ".\SupplementalPolicy$SuppPolicyName.xml" 
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "Supplemental Policy $SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)

                # Make sure policy rule options that don't belong to a Supplemental policy don't exit
                @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }
     
                Set-HVCIOptions -Strict -FilePath $SuppPolicyPath             
                Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version "1.0.0.0"            

                ConvertFrom-CIPolicy $SuppPolicyPath "$SuppPolicyID.cip" | Out-Null 
                CiTool --update-policy ".\$SuppPolicyID.cip" -json | Out-Null     
                &$WriteTeaGreen "`nSupplemental policy with the following details has been Deployed in Enforced Mode:"
                Write-Output "SupplementalPolicyName = $SuppPolicyName"
                Write-Output "SupplementalPolicyGUID = $SuppPolicyID"
                Remove-Item ".\$SuppPolicyID.cip" -Force
                Remove-Item -Path $PolicyPath -Force # Remove the policy xml file in Temp folder we created earlier         
            }
        }

        if ($MergeSupplementalPolicies) {        
            foreach ($PolicyPath in $PolicyPaths) {            
                ############ Input policy verification prior to doing anything ############
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {                                
                    $Supplementalxml = [xml](Get-Content $SuppPolicyPath)
                    $SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID
                    $SupplementalPolicyType = $Supplementalxml.SiPolicy.PolicyType
                    $DeployedPoliciesIDs = (CiTool -lp -json | ConvertFrom-Json).Policies.PolicyID | ForEach-Object { return "{$_}" }         
                    # Check the type of the user selected Supplemental policy XML files to make sure they are indeed Supplemental policies
                    if ($SupplementalPolicyType -ne "Supplemental Policy") {
                        Write-Error -Message "The Selected XML file with GUID $SupplementalPolicyID isn't a Supplemental Policy."
                    }
                    # Check to make sure the user selected Supplemental policy XML files are deployed on the system
                    if ($DeployedPoliciesIDs -notcontains $SupplementalPolicyID) {
                        Write-Error -Message "The Selected Supplemental XML file with GUID $SupplementalPolicyID isn't deployed on the system."
                    }
                }
                # Perform the merge
                Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath "$SuppPolicyName.xml" | Out-Null
                # Delete the deployed Supplemental policies that user selected from the system because we're going to deploy the new merged policy that contains all of them
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {                                
                    $Supplementalxml = [xml](Get-Content $SuppPolicyPath)
                    $SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID                         
                    Citool --remove-policy $SupplementalPolicyID -json | Out-Null
                    # remove the old policy files unless user chose to keep them
                    if (!$KeepOldSupplementalPolicies) { Remove-Item -Path $SuppPolicyPath -Force }        
                }
                # Prepare the final merged Supplemental policy for deployment           
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath "$SuppPolicyName.xml" -ResetPolicyID -PolicyName "$SuppPolicyName - $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)
                Set-HVCIOptions -Strict -FilePath "$SuppPolicyName.xml" 
                ConvertFrom-CIPolicy "$SuppPolicyName.xml" "$SuppPolicyID.cip" | Out-Null
                CiTool --update-policy "$SuppPolicyID.cip" -json | Out-Null              
                &$WriteTeaGreen "`nThe Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones.`nSystem Restart Not immediately needed but eventually required to finish the removal of previous individual Supplemental policies."
                Remove-Item -Path "$SuppPolicyID.cip" -Force
            }
        }

        if ($UpdateBasePolicy) {     
            # First get the Microsoft recommended driver block rules
            Invoke-Command -ScriptBlock $GetBlockRulesSCRIPTBLOCK | Out-Null            
   
            switch ($NewBasePolicyType) {
                "AllowMicrosoft_Plus_Block_Rules" {                      
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
                    Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Allow Microsoft Plus Block Rules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete } 
                }
                "Lightly_Managed_system_Policy" {                                          
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
                    Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Signed And Reputable policy refreshed on $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 6, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }            
                    # Configure required services for ISG authorization
                    Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -Wait -NoNewWindow
                    Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', "start= auto" -Wait -NoNewWindow
                }
                "DefaultWindows_WithBlockRules" {                                            
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml" -Destination ".\DefaultWindows_Enforced.xml"
                    # Scan PowerShell core directory and add them to the Default Windows base policy so that the module can be used after it's been deployed
                    if (Test-Path "C:\Program Files\PowerShell") {
                        Write-Host "Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it." -ForegroundColor Blue                    
                        New-CIPolicy -ScanPath "C:\Program Files\PowerShell" -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }
                    else {
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }     
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Default Windows Plus Block Rules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }
                }
            }

            if ($UpdateBasePolicy -and $RequireEVSigners) { Set-RuleOption -FilePath .\BasePolicy.xml -Option 8 }    

            Set-CIPolicyVersion -FilePath .\BasePolicy.xml -Version "1.0.0.1"
            Set-HVCIOptions -Strict -FilePath .\BasePolicy.xml
            
            # Remove the extra files create during module operation that are no longer necessary
            Remove-Item '.\AllowPowerShell.xml', '.\DefaultWindows_Enforced.xml', '.\AllowMicrosoft.xml' -Force -ErrorAction SilentlyContinue
            Remove-Item '.\Microsoft recommended block rules.xml' -Force

            # Get the policy ID of the currently deployed base policy based on the policy name that user selected
            $CurrentID = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.Friendlyname -eq $CurrentBasePolicyName }).BasePolicyID
            $CurrentID = "{$CurrentID}"
            Write-Debug -Message "This is the current ID of deployed base policy that is going to be used in the new base policy: $CurrentID"
            [xml]$xml = Get-Content ".\BasePolicy.xml"        
            $xml.SiPolicy.PolicyID = $CurrentID
            $xml.SiPolicy.BasePolicyID = $CurrentID
            $xml.Save(".\BasePolicy.xml")
            ConvertFrom-CIPolicy ".\BasePolicy.xml" "$CurrentID.cip" | Out-Null
            # Deploy the new base policy with the same GUID on the system
            CiTool --update-policy "$CurrentID.cip" -json | Out-Null
            # Remove the policy binary after it's been deployed
            Remove-Item "$CurrentID.cip" -Force
            
            # Keep the new base policy XML file that was just deployed, in the current directory, so user can keep it for later 
            $PolicyFiles = @{
                "AllowMicrosoft_Plus_Block_Rules" = "AllowMicrosoftPlusBlockRules.xml"
                "Lightly_Managed_system_Policy"   = "SignedAndReputable.xml"
                "DefaultWindows_WithBlockRules"   = "DefaultWindowsPlusBlockRules.xml"
            }
            Remove-Item $PolicyFiles[$NewBasePolicyType] -Force -ErrorAction SilentlyContinue
            Rename-Item -Path ".\BasePolicy.xml" -NewName $PolicyFiles[$NewBasePolicyType] -Force
            &$WriteSubtleRainbow "Base Policy has been successfully updated to $NewBasePolicyType"
            &$WriteLavender "Keep in mind that your previous policy path saved in User Configurations is no longer valid as you just changed your Base policy."
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

#>
}

# Importing argument completer ScriptBlocks
. "$psscriptroot\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName "Edit-WDACConfig" -ParameterName "PolicyPaths" -ScriptBlock $ArgumentCompleterPolicyPathsBasePoliciesOnly
Register-ArgumentCompleter -CommandName "Edit-WDACConfig" -ParameterName "SuppPolicyPaths" -ScriptBlock $ArgumentCompleterPolicyPathsSupplementalPoliciesOnly