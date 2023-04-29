#Requires -RunAsAdministrator
function Edit-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = "Allow New Apps Audit Events",
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")][switch]$AllowNewAppsAuditEvents,
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")][switch]$AllowNewApps,
        [Parameter(Mandatory = $false, ParameterSetName = "Merge Supplemental Policies")][switch]$MergeSupplementalPolicies,
        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy")][switch]$UpdateBasePolicy,

        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [string]$SuppPolicyName,
        
        [ValidatePattern('.*\.xml')]
        [ValidateScript({
                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to
                # Edit a Signed policy using Edit-WDACConfig cmdlet which is only made for Unsigned policies
                $_ | ForEach-Object {                   
                    $xmlTest = [xml](Get-Content $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if (!$RedFlag1 -or !$RedFlag2) { return $True }                     
                }
            }, ErrorMessage = "The policy XML file(s) you chose are Signed policies. Please use Edit-SignedWDACConfig cmdlet to edit Signed policies.")]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [string[]]$PolicyPaths,

        [ValidatePattern('.*\.xml')]        
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [string[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [switch]$Debugmode,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [string]$Levels,

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [string[]]$Fallbacks,

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [switch]$NoScript,

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [switch]$NoUserPEs,

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [switch]$AllowFileNameFallbacks,
        
        [ValidateSet("OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [string]$SpecificFileNameLevel,
        # Setting the maxim range to the maximum allowed log size by Windows Event viewer
        [ValidateRange(1024KB, 18014398509481983KB)]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [Int64]$LogSize,

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")][switch]$IncludeDeletedFiles,

        [ValidateSet([BasePolicyNamez])]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")][string[]]$CurrentBasePolicyName,

        [ValidateSet("AllowMicrosoft_Plus_Block_Rules", "Lightly_Managed_system_Policy", "DefaultWindows_WithBlockRules")]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")][string]$NewBasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy")][switch]$RequireEVSigners,

        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # argument tab auto-completion and ValidateSet for Policy names 
        Class BasePolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
            [string[]] GetValidValues() {
                $BasePolicyNamez = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.PolicyID -eq $_.BasePolicyID }).Friendlyname
           
                return [string[]]$BasePolicyNamez
            }
        }

        # argument tab auto-completion and ValidateSet for Fallbacks
        Class Fallbackz : System.Management.Automation.IValidateSetValuesGenerator {
            [string[]] GetValidValues() {
                $Fallbackz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
   
                return [string[]]$Fallbackz
            }
        }

        # argument tab auto-completion and ValidateSet for levels
        Class Levelz : System.Management.Automation.IValidateSetValuesGenerator {
            [string[]] GetValidValues() {
                $Levelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
       
                return [string[]]$Levelz
            }
        }

        # Redeploy the base policy in Enforcement mode
        function Update-BasePolicyToEnforcement {        
            Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete
            ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null        
            CiTool --update-policy ".\$PolicyID.cip" -json
            Remove-Item ".\$PolicyID.cip" -Force
            Write-host "`n`nThe Base policy with the following details has been Re-Deployed in Enforcement Mode:" -ForegroundColor Green        
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID`n"
        }

        $Get_BlockRulesSCRIPTBLOCK = {             
            $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md"
            $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)" | Out-Null
            $Rules = $Matches[0]

            $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_1"\sFriendlyName="Allow\sKernel\sDrivers"\sFileName="\*".*/>', ''
            $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_2"\sFriendlyName="Allow\sUser\smode\scomponents"\sFileName="\*".*/>', ''
            $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_1".*/>', ''
            $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_2".*/>', ''

            $Rules | Out-File '.\Microsoft recommended block rules TEMP.xml'

            Get-Content '.\Microsoft recommended block rules TEMP.xml' | Where-Object { $_.trim() -ne "" } | Out-File '.\Microsoft recommended block rules.xml'                
            Remove-Item '.\Microsoft recommended block rules TEMP.xml' -Force
            Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option 3 -Delete
            Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.xml'
            [PSCustomObject]@{
                PolicyFile = 'Microsoft recommended block rules.xml'
            }
        }

        # Stop operation as soon as there is an error, anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { . Update-self }       
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
                # defining Base policy
                $xml = [xml](Get-Content $PolicyPath)            
                $PolicyID = $xml.SiPolicy.PolicyID
                $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object { $_.provider -eq "PolicyInfo" -and $_.valuename -eq "Name" -and $_.key -eq "Information" }).value.string
    
                # Remove any cip file if there is any
                Remove-Item -Path ".\$PolicyID.cip" -ErrorAction SilentlyContinue
                Set-RuleOption -FilePath $PolicyPath -Option 3
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force            
                Write-host "`n`nThe Base policy with the following details has been Re-Deployed in Audit Mode:" -ForegroundColor Green        
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID"
    
                ################################### User Interaction ####################################            
                Write-host "`nAudit mode deployed, start installing your programs now" -ForegroundColor Magenta    
                Write-Host "When you've finished installing programs, Press Enter to start selecting program directories to scan`n" -ForegroundColor Blue
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
                
                # Only proceed if user selected at least 1 folder path
                if (-NOT ($ProgramsPaths.count -eq 0)) {
        
                    Write-Host "Here are the paths you selected:" -ForegroundColor Yellow
                    $ProgramsPaths | ForEach-Object { $_ }
    
                    #Process Program Folders From User input
                    
                    $AssignedLevels = $null
                    switch ($Levels) {
                        'Hash' { $AssignedLevels = 'Hash' }
                        'FileName' { $AssignedLevels = 'FileName' }
                        'SignedVersion' { $AssignedLevels = 'SignedVersion' }
                        'Publisher' { $AssignedLevels = 'Publisher' }
                        'FilePublisher' { $AssignedLevels = 'FilePublisher' }
                        'LeafCertificate' { $AssignedLevels = 'LeafCertificate' }
                        'PcaCertificate' { $AssignedLevels = 'PcaCertificate' }
                        'RootCertificate' { $AssignedLevels = 'RootCertificate' }
                        'WHQL' { $AssignedLevels = 'WHQL' }
                        'WHQLPublisher' { $AssignedLevels = 'WHQLPublisher' }
                        'WHQLFilePublisher' { $AssignedLevels = 'WHQLFilePublisher' }
                        'PFN' { $AssignedLevels = 'PFN' }
                        'FilePath' { $AssignedLevels = 'FilePath' }
                        'None' { $AssignedLevels = 'None' }
                        Default { $AssignedLevels = 'FilePublisher' }
                    }

                    $AssignedFallbacks = @()
                    switch ($Fallbacks) {
                        'Hash' { $AssignedFallbacks += 'Hash' }
                        'FileName' { $AssignedFallbacks += 'FileName' }
                        'SignedVersion' { $AssignedFallbacks += 'SignedVersion' }
                        'Publisher' { $AssignedFallbacks += 'Publisher' }
                        'FilePublisher' { $AssignedFallbacks += 'FilePublisher' }
                        'LeafCertificate' { $AssignedFallbacks += 'LeafCertificate' }
                        'PcaCertificate' { $AssignedFallbacks += 'PcaCertificate' }
                        'RootCertificate' { $AssignedFallbacks += 'RootCertificate' }
                        'WHQL' { $AssignedFallbacks += 'WHQL' }
                        'WHQLPublisher' { $AssignedFallbacks += 'WHQLPublisher' }
                        'WHQLFilePublisher' { $AssignedFallbacks += 'WHQLFilePublisher' }
                        'PFN' { $AssignedFallbacks += 'PFN' }
                        'FilePath' { $AssignedFallbacks += 'FilePath' }
                        'None' { $AssignedFallbacks += 'None' }
                        Default { $AssignedFallbacks += 'Hash' }
                    }
                    # Scan each of the folder paths that user selected
                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        $UserInputProgramFoldersPolicyMakerHashTable = @{
                            FilePath             = ".\ProgramDir_ScanResults$($i).xml"
                            ScanPath             = $ProgramsPaths[$i]
                            Level                = $AssignedLevels
                            Fallback             = $AssignedFallbacks
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
    
                    Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\SupplementalPolicy$SuppPolicyName.xml" | Out-Null                                  
                
                    #Re-Deploy-Basepolicy-in-Enforcement-mode
                    Update-BasePolicyToEnforcement      
    
                    Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force 
    
                    #Supplemental-policy-processing-and-deployment
        
                    $SuppPolicyPath = ".\SupplementalPolicy$SuppPolicyName.xml" 
                    $SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "Supplemental Policy $SuppPolicyName made on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                    $SuppPolicyID = $SuppPolicyID.Substring(11)                
    
                    # Make sure policy rule options that don't belong to a Supplemental policy don't exit
                    @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }
     
                    Set-HVCIOptions -Strict -FilePath $SuppPolicyPath             
                    Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version "1.0.0.0"            
    
                    ConvertFrom-CIPolicy $SuppPolicyPath "$SuppPolicyID.cip" | Out-Null 
                    CiTool --update-policy ".\$SuppPolicyID.cip" -json
                    Remove-Item ".\$SuppPolicyID.cip" -Force

                    Write-host "`nSupplemental policy with the following details has been Deployed in Enforcement Mode:" -ForegroundColor Green
                                
                    [PSCustomObject]@{
                        SupplementalPolicyName = $SuppPolicyName
                        SupplementalPolicyGUID = $SuppPolicyID
                    }

                }            
                # Do this if no program path(s) was selected by user
                else {
                    Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Magenta
                    #Re-Deploy-Basepolicy-in-Enforcement-mode
                    Update-BasePolicyToEnforcement                 
                    break
                }
            }
        }

        if ($AllowNewAppsAuditEvents) {
            # Change Code Integrity event logs size
            if ($AllowNewAppsAuditEvents -and $LogSize) { . Set-LogSize -LogSize $LogSize }
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
                # defining Base policy
                $xml = [xml](Get-Content $PolicyPath)            
                $PolicyID = $xml.SiPolicy.PolicyID
                $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object { $_.provider -eq "PolicyInfo" -and $_.valuename -eq "Name" -and $_.key -eq "Information" }).value.string

                # Remove any cip file if any
                Remove-Item -Path ".\$PolicyID.cip" -ErrorAction SilentlyContinue       
                Set-RuleOption -FilePath $PolicyPath -Option 3
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null            
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force
                Write-host "`n`nThe Base policy with the following details has been Re-Deployed in Audit Mode:" -ForegroundColor Green        
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID"

                ################################### Get the Levels and Fallbacks from User inputs ###################################
                $AssignedLevels = $null
                switch ($Levels) {
                    'Hash' { $AssignedLevels = 'Hash' }
                    'FileName' { $AssignedLevels = 'FileName' }
                    'SignedVersion' { $AssignedLevels = 'SignedVersion' }
                    'Publisher' { $AssignedLevels = 'Publisher' }
                    'FilePublisher' { $AssignedLevels = 'FilePublisher' }
                    'LeafCertificate' { $AssignedLevels = 'LeafCertificate' }
                    'PcaCertificate' { $AssignedLevels = 'PcaCertificate' }
                    'RootCertificate' { $AssignedLevels = 'RootCertificate' }
                    'WHQL' { $AssignedLevels = 'WHQL' }
                    'WHQLPublisher' { $AssignedLevels = 'WHQLPublisher' }
                    'WHQLFilePublisher' { $AssignedLevels = 'WHQLFilePublisher' }
                    'PFN' { $AssignedLevels = 'PFN' }
                    'FilePath' { $AssignedLevels = 'FilePath' }
                    'None' { $AssignedLevels = 'None' }
                    Default { $AssignedLevels = 'FilePublisher' }
                }

                $AssignedFallbacks = @()
                switch ($Fallbacks) {
                    'Hash' { $AssignedFallbacks += 'Hash' }
                    'FileName' { $AssignedFallbacks += 'FileName' }
                    'SignedVersion' { $AssignedFallbacks += 'SignedVersion' }
                    'Publisher' { $AssignedFallbacks += 'Publisher' }
                    'FilePublisher' { $AssignedFallbacks += 'FilePublisher' }
                    'LeafCertificate' { $AssignedFallbacks += 'LeafCertificate' }
                    'PcaCertificate' { $AssignedFallbacks += 'PcaCertificate' }
                    'RootCertificate' { $AssignedFallbacks += 'RootCertificate' }
                    'WHQL' { $AssignedFallbacks += 'WHQL' }
                    'WHQLPublisher' { $AssignedFallbacks += 'WHQLPublisher' }
                    'WHQLFilePublisher' { $AssignedFallbacks += 'WHQLFilePublisher' }
                    'PFN' { $AssignedFallbacks += 'PFN' }
                    'FilePath' { $AssignedFallbacks += 'FilePath' }
                    'None' { $AssignedFallbacks += 'None' }
                    Default { $AssignedFallbacks += 'Hash' }
                }
             
                ################################### User Interaction ####################################
                Write-host "`nAudit mode deployed, start installing your programs now" -ForegroundColor Magenta        
                Write-Host "When you've finished installing programs, Press Enter to start selecting program directories to scan`n" -ForegroundColor Blue
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
                if (-NOT ($ProgramsPaths.count -eq 0)) {
                    Write-Host "Here are the paths you selected:" -ForegroundColor Yellow
                    $ProgramsPaths | ForEach-Object { $_ }

                    ################################### EventCapturing ################################

                    Write-host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan    

                    # The notice about variable being assigned and never used should be ignored - it's being dot-sourced from Resources file                    
                    $DirveLettersGlobalRootFix = Invoke-Command -ScriptBlock $DirveLettersGlobalRootFixScriptBlock

                    # Defining the same arrays that exist in $AuditEventLogsProcessingScriptBlock, outside of it, to store its results separately
                    $DeletedFileHashesArray = @()
                    $AvailableFilesPathsArray = @()  

                    # Extracting the array content from inside of the $AuditEventLogsProcessingScriptBlock ScripBlock by assigning each data to a separate array
                    $DeletedFileHashesArray, $AvailableFilesPathsArray = Invoke-Command -ScriptBlock $AuditEventLogsProcessingScriptBlock
                            
                    # Only create policy for files that are available on the disk based on Event viewer logs if there are any
                    if ($AvailableFilesPathsArray) {
                        # Create a folder in Temp directory to copy the files that are not included in user-selected program path(s)
                        # but detected in Event viewer audit logs, scan that folder, and in the end delete it                   
                        New-Item -Path "$env:TEMP\TemporaryScanFolderForEventViewerFiles" -ItemType Directory | Out-Null
                        # Using the function to find out which files are not in the user-selected path(s) to only scan those, this prevents duplicate rule creation and double file copying
                        (. Test-FilePath -FilePath $AvailableFilesPathsArray -DirectoryPath $ProgramsPaths).path | Select-Object -Unique | ForEach-Object {                             
                            Copy-Item -Path $_ -Destination "$env:TEMP\TemporaryScanFolderForEventViewerFiles\" -ErrorAction SilentlyContinue                       
                        }
                      
                        # Create a policy XML file for available files on the disk

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        $AvailableFilesOnDiskPolicyMakerHashTable = @{
                            FilePath             = ".\RulesForFilesNotInUserSelectedPaths.xml"
                            ScanPath             = "$env:TEMP\TemporaryScanFolderForEventViewerFiles\"
                            Level                = $AssignedLevels
                            Fallback             = $AssignedFallbacks
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
                                    
                    # Only create policy for files that are on longer available on the disk if there are any and
                    # if user chose to include deleted files in the final supplemental policy
                    if ($DeletedFileHashesArray -and $IncludeDeletedFiles) {

                        # Create File Rules based on hash of the files and store them in the $Rules variable
                        $i = 1
                        $imax = ($DeletedFileHashesArray).count
                        while ($i -le $imax) {
                            $DeletedFileHashesArray | ForEach-Object {  
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AA_$i`" FriendlyName=`"$($_.'File Name') SHA256 Hash`" Hash=`"$($_.'SHA256 Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AB_$i`" FriendlyName=`"$($_.'File Name') SHA256 Flat Hash`" Hash=`"$($_.'SHA256 Flat Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AC_$i`" FriendlyName=`"$($_.'File Name') SHA1 Hash`" Hash=`"$($_.'SHA1 Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AD_$i`" FriendlyName=`"$($_.'File Name') SHA1 Flat Hash`" Hash=`"$($_.'SHA1 Flat Hash')`" />"
                                $i++
                            }
                        }
                        # Create File Rule Refs based on the ID of the File Rules above and store them in the $RulesRefs variable
                        $i = 1
                        $imax = ($DeletedFileHashesArray).count
                        while ($i -le $imax) {
                            $DeletedFileHashesArray | ForEach-Object { 
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AA_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AB_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AC_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AD_$i`" />"
                                $i++
                            }
                        }  
                        # Save the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the current working directory for debugging purposes
                        $Rules + $RulesRefs | Out-File FileRulesAndFileRefs.txt
                        # An empty base policy content
                        $EmptyPolicy = @"
<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
<VersionEx>10.0.0.0</VersionEx>
<PlatformID>{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}</PlatformID>
<Rules>
<Rule>
<Option>Enabled:Unsigned System Integrity Policy</Option>
</Rule>
<Rule>
<Option>Enabled:Audit Mode</Option>
</Rule>
<Rule>
<Option>Enabled:Advanced Boot Options Menu</Option>
</Rule>
<Rule>
<Option>Required:Enforce Store Applications</Option>
</Rule>
</Rules>
<!--EKUS-->
<EKUs />
<!--File Rules-->
<FileRules>
$Rules
</FileRules>
<!--Signers-->
<Signers />
<!--Driver Signing Scenarios-->
<SigningScenarios>
<SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS_1" FriendlyName="Auto generated policy on $(Get-Date -Format 'MM-dd-yyyy')">
<ProductSigners />
</SigningScenario>
<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on $(Get-Date -Format 'MM-dd-yyyy')">
<ProductSigners>
<FileRulesRef>
$RulesRefs
</FileRulesRef>
</ProductSigners>
</SigningScenario>
</SigningScenarios>
<UpdatePolicySigners />
<CiSigners />
<HvciOptions>0</HvciOptions>
<BasePolicyID>{B163125F-E30A-43FC-ABEC-E30B4EE88FA8}</BasePolicyID>
<PolicyID>{B163125F-E30A-43FC-ABEC-E30B4EE88FA8}</PolicyID>
</SiPolicy>
"@                      
                        $EmptyPolicy | Out-File .\DeletedFileHashesEventsPolicy.xml                    
                        # adding the policy file that consists of rules from audit even logs, to the array
                        $PolicyXMLFilesArray += ".\DeletedFileHashesEventsPolicy.xml"
                    }
                                      
                    ######################## Process Program Folders From User input #####################
                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        $UserInputProgramFoldersPolicyMakerHashTable = @{
                            FilePath             = ".\ProgramDir_ScanResults$($i).xml"
                            ScanPath             = $ProgramsPaths[$i]
                            Level                = $AssignedLevels
                            Fallback             = $AssignedFallbacks
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
                    # Merge all of the policy XML files in the array into the final Supplemental policy
                    Merge-CIPolicy -PolicyPaths $PolicyXMLFilesArray -OutputFilePath ".\SupplementalPolicy$SuppPolicyName.xml" | Out-Null     
                }
                # Exit the operation if user didn't select any folder paths
                else {                                      
                    Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Red
                    #Re-Deploy-Basepolicy-in-Enforcement-mode
                    Update-BasePolicyToEnforcement
                    break
                }
                # Delete these extra files unless user uses -Debugmode optional parameter
                if (-NOT $Debugmode) {
                    Remove-Item -Path ".\FileRulesAndFileRefs.txt" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path "DeletedFileHashesEventsPolicy.xml" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force  -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\RulesForFilesNotInUserSelectedPaths.xml" -Force -ErrorAction SilentlyContinue
                }

                #Re-Deploy-Basepolicy-in-Enforcement-mode
                Update-BasePolicyToEnforcement  

                #################### Supplemental-policy-processing-and-deployment ############################

                $SuppPolicyPath = ".\SupplementalPolicy$SuppPolicyName.xml" 
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "Supplemental Policy $SuppPolicyName made on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)

                # Make sure policy rule options that don't belong to a Supplemental policy don't exit
                @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }
     
                Set-HVCIOptions -Strict -FilePath $SuppPolicyPath             
                Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version "1.0.0.0"            

                ConvertFrom-CIPolicy $SuppPolicyPath "$SuppPolicyID.cip" | Out-Null 
                CiTool --update-policy ".\$SuppPolicyID.cip" -json
                Remove-Item ".\$SuppPolicyID.cip" -Force            
                Write-host "`nSupplemental policy with the following details has been Deployed in Enforcement Mode:" -ForegroundColor Green
                # create an object to display on the console
                [PSCustomObject]@{
                    SupplementalPolicyName = $SuppPolicyName
                    SupplementalPolicyGUID = $SuppPolicyID
                }             
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
                        Write-Error "The Selected XML file with GUID $SupplementalPolicyID isn't a Supplemental Policy."
                        break
                    }
                    # Check to make sure the user selected Supplemental policy XML files are deployed on the system
                    if ($DeployedPoliciesIDs -notcontains $SupplementalPolicyID) {
                        Write-Error "The Selected Supplemental XML file with GUID $SupplementalPolicyID isn't deployed on the system."
                        break
                    }
                }
                # Perform the merge
                Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath "$SuppPolicyName.xml" | Out-Null
                # Delete the deployed Supplemental policies that user selected from the system because we're going to deploy the new merged policy that contains all of them
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {                                
                    $Supplementalxml = [xml](Get-Content $SuppPolicyPath)
                    $SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID                         
                    citool --remove-policy $SupplementalPolicyID -json | Out-Null                
                }
                # Prepare the final merged Supplemental policy for deployment           
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath "$SuppPolicyName.xml" -ResetPolicyID -PolicyName "$SuppPolicyName Merged on $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)
                Set-HVCIOptions -Strict -FilePath "$SuppPolicyName.xml" 
                ConvertFrom-CIPolicy "$SuppPolicyName.xml" "$SuppPolicyID.cip" | Out-Null
                CiTool --update-policy "$SuppPolicyID.cip" -json
                Write-Host "`nThe Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones, please restart your system." -ForegroundColor Green
            }
        }

        if ($UpdateBasePolicy) {     
            # First get the Microsoft recommended driver block rules
            Invoke-Command -ScriptBlock $Get_BlockRulesSCRIPTBLOCK | Out-Null            
   
            switch ($NewBasePolicyType) {
                "AllowMicrosoft_Plus_Block_Rules" {                      
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
                    Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "AllowMicrosoftPlusBlockRules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete } 
                }
                "Lightly_Managed_system_Policy" {                                          
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
                    Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "SignedAndReputable policy refreshed on $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 6, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }            
                    appidtel start
                    sc.exe config appidsvc start= auto
                }
                "DefaultWindows_WithBlockRules" {                                            
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml" -Destination ".\DefaultWindows_Enforced.xml"
                    # Scan PowerShell core directory and add them to the Default Windows base policy so that the module can be used after it's been deployed
                    if (Test-Path "C:\Program Files\PowerShell") {
                        Write-Host "Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it." -ForegroundColor Blue                    
                        New-CIPolicy -ScanPath "C:\Program Files\PowerShell" -Level FilePublisher -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }
                    else {
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }     
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "DefaultWindowsPlusBlockRules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }
                }
            }

            if ($UpdateBasePolicy -and $RequireEVSigners) { Set-RuleOption -FilePath .\BasePolicy.xml -Option 8 }    

            Set-CIPolicyVersion -FilePath .\BasePolicy.xml -Version "1.0.0.1"
            Set-HVCIOptions -Strict -FilePath .\BasePolicy.xml
            
            # Remove the extra files create during module operation that are no longer necessary
            Remove-Item .\AllowPowerShell.xml -Force -ErrorAction SilentlyContinue
            Remove-Item .\DefaultWindows_Enforced.xml -Force -ErrorAction SilentlyContinue
            Remove-Item .\AllowMicrosoft.xml -Force -ErrorAction SilentlyContinue
            Remove-Item '.\Microsoft recommended block rules.xml' -Force

            # Get the policy ID of the currently deployed base policy based on the policy name that user selected
            $CurrentID = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.Friendlyname -eq $CurrentBasePolicyName }).BasePolicyID
            $CurrentID = "{$CurrentID}"
            [xml]$xml = Get-Content ".\BasePolicy.xml"        
            $xml.SiPolicy.PolicyID = $CurrentID
            $xml.SiPolicy.BasePolicyID = $CurrentID
            $xml.Save(".\BasePolicy.xml")
            ConvertFrom-CIPolicy ".\BasePolicy.xml" "$CurrentID.cip" | Out-Null
            # Deploy the new base policy with the same GUID on the system
            CiTool --update-policy "$CurrentID.cip" -json
            # Remove the policy binary after it's been deployed
            Remove-Item "$CurrentID.cip" -Force
            
            # Keep the new base policy XML file that was just deployed, in the current directory, so user can keep it for later 
            switch ($NewBasePolicyType) {
                "AllowMicrosoft_Plus_Block_Rules" { Rename-Item -Path ".\BasePolicy.xml" -NewName "AllowMicrosoftPlusBlockRules.xml" }
                "Lightly_Managed_system_Policy" { Rename-Item -Path ".\BasePolicy.xml" -NewName "SignedAndReputable.xml" }
                "DefaultWindows_WithBlockRules" { Rename-Item -Path ".\BasePolicy.xml" -NewName "DefaultWindowsPlusBlockRules.xml" }
            }
        }
    }

    <#
.SYNOPSIS
Edits non-signed WDAC policies deployed on the system

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig

.DESCRIPTION
Using official Microsoft methods, Edits non-signed WDAC policies deployed on the system

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Using official Microsoft methods, Edits non-signed WDAC policies deployed on the system

.PARAMETER AllowNewApps
While an unsigned WDAC policy is already deployed on the system, rebootlessly turn on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked.

.PARAMETER AllowNewAppsAuditEvents
While an unsigned WDAC policy is already deployed on the system, rebootlessly turn on Audit mode in it, which will allow you to install a new app that was otherwise getting blocked.

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

.PARAMETER MergeSupplementalPolicies
Merges multiple deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one. System restart needed to take effect.

.PARAMETER UpdateBasePolicy
It can rebootlessly change the type of the deployed base policy. It can update the recommended block rules and/or change policy rule options in the deployed base policy.

#>
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete


# argument tab auto-completion for Policy Paths to show only .xml files and only base policies
$ArgumentCompleterPolicyPaths = {
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | ForEach-Object {
        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq "Base Policy") { $_ }
    } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Edit-WDACConfig" -ParameterName "PolicyPaths" -ScriptBlock $ArgumentCompleterPolicyPaths


# argument tab auto-completion for Supplemental Policy Paths to show only .xml files and only Supplemental policies
$ArgumentCompleterSuppPolicyPaths = {
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | ForEach-Object {
        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq "Supplemental Policy") { $_ }
    } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Edit-WDACConfig" -ParameterName "SuppPolicyPaths" -ScriptBlock $ArgumentCompleterSuppPolicyPaths
