#Requires -RunAsAdministrator
function Edit-SignedWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = "Allow New Apps Audit Events",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")][Switch]$AllowNewAppsAuditEvents,
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")][Switch]$AllowNewApps,
        [Parameter(Mandatory = $false, ParameterSetName = "Merge Supplemental Policies")][Switch]$MergeSupplementalPolicies,        
        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy")][Switch]$UpdateBasePolicy,

        [ValidatePattern('\.cer$')]
        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = "The path you selected is not a file path.")]        
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy", ValueFromPipelineByPropertyName = $true)] 
        [System.String]$CertPath,

        [ValidatePattern('^[a-zA-Z0-9 ]+$', ErrorMessage = "The Supplemental Policy Name can only contain alphanumeric characters.")]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]       
        [System.String]$SuppPolicyName,        

        [ValidatePattern('\.xml$')]
        [ValidateScript({
                # Validate each Policy file in PolicyPaths parameter to make sure the user isn't accidentally trying to
                # Edit an Unsigned policy using Edit-SignedWDACConfig cmdlet which is only made for Signed policies
                $_ | ForEach-Object {                   
                    $xmlTest = [xml](Get-Content $_)
                    $RedFlag1 = $xmlTest.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
                    $RedFlag2 = $xmlTest.SiPolicy.UpdatePolicySigners.UpdatePolicySigner.SignerId
                    if ($RedFlag1 -or $RedFlag2) { return $True }                   
                }
            }, ErrorMessage = "The policy XML file(s) you chose are Unsigned policies. Please use Edit-WDACConfig cmdlet to edit Unsigned policies.")]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]     
        [System.String[]]$PolicyPaths,

        [ValidateScript({
                try {
                    # TryCatch to show a custom error message instead of saying input is null when personal store is empty 
                ((Get-ChildItem -ErrorAction Stop -Path 'Cert:\CurrentUser\My').Subject.Substring(3)) -contains $_            
                }
                catch {
                    Write-Error -Message "A certificate with the provided common name doesn't exist in the personal store of the user certificates."
                } # this error msg is shown when cert CN is not available in the personal store of the user certs
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy", ValueFromPipelineByPropertyName = $true)]
        [System.String]$CertCN,

        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = "The path you selected is not a file path.")]
        [Parameter(Mandatory = $true, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [System.String[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = "Merge Supplemental Policies")]
        [switch]$KeepOldSupplementalPolicies,

        # Setting the maxim range to the maximum allowed log size by Windows Event viewer
        [ValidateRange(1024KB, 18014398509481983KB)][Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [System.Int64]$LogSize,

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

        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")][Switch]$IncludeDeletedFiles,

        [ValidateSet([BasePolicyNamez])]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")]
        [System.String[]]$CurrentBasePolicyName,

        [ValidateSet("AllowMicrosoft_Plus_Block_Rules", "Lightly_Managed_system_Policy", "DefaultWindows_WithBlockRules")]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")]
        [System.String]$NewBasePolicyType,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [System.String]$Level = "FilePublisher", # Setting the default value for the Level parameter

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [parameter(Mandatory = $false, ParameterSetName = "Allow New Apps")]
        [System.String[]]$Fallbacks,

        [ValidatePattern('\.exe$')]
        [ValidateScript({ # Setting the minimum version of SignTool that is allowed to be executed as well as other checks
                [System.Version]$WindowsSdkVersion = '10.0.22621.755'
                (((get-item -Path $_).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
                (((get-item -Path $_).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
                ((get-item -Path $_).VersionInfo).CompanyName -eq 'Microsoft Corporation'
                ((Get-AuthenticodeSignature -FilePath $_).Status -eq 'Valid')
                ((Get-AuthenticodeSignature -FilePath $_).StatusMessage -eq 'Signature verified.')
            }, ErrorMessage = "The SignTool executable was found but couldn't be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK")]
        [parameter(ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Merge Supplemental Policies", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy", ValueFromPipelineByPropertyName = $true)]
        [System.String]$SignToolPath,

        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy")]
        [Switch]$RequireEVSigners,

        [Parameter(Mandatory = $false)]
        [Switch]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # Detecting if Debug switch is used, will do debugging actions based on that
        $Debug = $PSBoundParameters.Debug.IsPresent

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
        
        #Re-Deploy Basepolicy in Enforced mode
        function Update-BasePolicyToEnforced {        
            Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
            Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete
            ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null            
            
            # Configure the parameter splat
            $ProcessParams = @{
                'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$PolicyID.cip"
                'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))
                'NoNewWindow'  = $true
                'Wait'         = $true
            }
            # Sign the files with the specified cert
            Start-Process @ProcessParams

            Remove-Item ".\$PolicyID.cip" -Force            
            Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
            CiTool --update-policy ".\$PolicyID.cip" -json
            Remove-Item ".\$PolicyID.cip" -Force
            Write-host "`n`nThe Base policy with the following details has been Re-Signed and Re-Deployed in Enforced Mode:" -ForegroundColor Green        
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID`n"
        }

        # Stop operation as soon as there is an error, anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { . Update-self }

        $DirveLettersGlobalRootFix = Invoke-Command -ScriptBlock $DirveLettersGlobalRootFixScriptBlock
    }

    process {
                            
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
                # defining Base policy
                $xml = [xml](Get-Content $PolicyPath)            
                $PolicyID = $xml.SiPolicy.PolicyID
                $PolicyName = ($xml.SiPolicy.Settings.Setting | Where-Object { $_.provider -eq "PolicyInfo" -and $_.valuename -eq "Name" -and $_.key -eq "Information" }).value.string

                # Remove any cip file if there is any
                Remove-Item -Path ".\$PolicyID.cip" -ErrorAction SilentlyContinue
                Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete        
                Set-RuleOption -FilePath $PolicyPath -Option 3
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null
                
                # Configure the parameter splat
                $ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$PolicyID.cip"
                    'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                }
                # Sign the files with the specified cert
                Start-Process @ProcessParams
            
                Remove-Item ".\$PolicyID.cip" -Force         
                Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force
                Write-host "`n`nThe Base policy with the following details has been Re-Signed and Re-Deployed in Audit Mode:" -ForegroundColor Green        
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
               
                # Make sure User browsed for at least 1 directory
                if (-NOT ($ProgramsPaths.count -eq 0)) {
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
                            
                            $TestFilePathResults | ForEach-Object {                             
                                Copy-Item -Path $_ -Destination "$env:TEMP\TemporaryScanFolderForEventViewerFiles\" -ErrorAction SilentlyContinue
                                Write-Debug -Message "The following file is being copied to the TEMP directory for scanning because it was found in event logs but didn't exist in any of the user-selected paths: $_ "                      
                            }
                      
                            # Create a policy XML file for available files on the disk

                            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                            [System.Collections.Hashtable]$AvailableFilesOnDiskPolicyMakerHashTable = @{
                                FilePath             = ".\RulesForFilesNotInUserSelectedPaths.xml"
                                ScanPath             = "$env:TEMP\TemporaryScanFolderForEventViewerFiles\"
                                Level                = $Level
                                Fallback             = $Fallbacks ? (Get-Fallbacks -Fallbacks $Fallbacks) : 'Hash'
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

                        # Create File Rules based on hash of the files and store them in the $Rules variable
                        $i = 1
                        $imax = ($AuditEventLogsProcessingResults.DeletedFileHashes).count
                        while ($i -le $imax) {
                            $AuditEventLogsProcessingResults.DeletedFileHashes | ForEach-Object {  
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AA_$i`" FriendlyName=`"$($_.'File Name') SHA256 Hash`" Hash=`"$($_.'SHA256 Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AB_$i`" FriendlyName=`"$($_.'File Name') SHA256 Flat Hash`" Hash=`"$($_.'SHA256 Flat Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AC_$i`" FriendlyName=`"$($_.'File Name') SHA1 Hash`" Hash=`"$($_.'SHA1 Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AD_$i`" FriendlyName=`"$($_.'File Name') SHA1 Flat Hash`" Hash=`"$($_.'SHA1 Flat Hash')`" />"
                                $i++
                            }
                        }
                        # Create File Rule Refs based on the ID of the File Rules above and store them in the $RulesRefs variable
                        $i = 1
                        $imax = ($AuditEventLogsProcessingResults.DeletedFileHashes).count
                        while ($i -le $imax) {
                            $AuditEventLogsProcessingResults.DeletedFileHashes | ForEach-Object { 
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AA_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AB_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AC_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AD_$i`" />"
                                $i++
                            }
                        }  
                        # Save the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the current working directory for debugging purposes
                        $Rules + $RulesRefs | Out-File FileRulesAndFileRefs.txt

                        # Put the Rules and RulesRefs in an empty policy file
                        New-EmptyPolicy -RulesContent $Rules -RuleRefsContent $RulesRefs | Out-File .\DeletedFileHashesEventsPolicy.xml
           
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
                            Fallback             = $Fallbacks ? (Get-Fallbacks -Fallbacks $Fallbacks) : 'Hash'
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
                                        $getletter = $DirveLettersGlobalRootFix | Where-Object { $_.devicepath -eq "\Device\HarddiskVolume$hardDiskVolumeNumber" }
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

                            # Create File Rules based on hash of the files and store them in the $Rules variable
                            $i = 1
                            $Rules = @()
                            $imax = ($KernelProtectedHashesBlockResults).count
                            while ($i -le $imax) {
                                $KernelProtectedHashesBlockResults | ForEach-Object {  
                                    $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AA_$i`" FriendlyName=`"$($_.'File Name') SHA256 Hash`" Hash=`"$($_.'SHA256 Hash')`" />"
                                    $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AB_$i`" FriendlyName=`"$($_.'File Name') SHA256 Flat Hash`" Hash=`"$($_.'SHA256 Flat Hash')`" />"
                                    $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AC_$i`" FriendlyName=`"$($_.'File Name') SHA1 Hash`" Hash=`"$($_.'SHA1 Hash')`" />"
                                    $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AD_$i`" FriendlyName=`"$($_.'File Name') SHA1 Flat Hash`" Hash=`"$($_.'SHA1 Flat Hash')`" />"
                                    $i++
                                }
                            }
                            # Create File Rule Refs based on the ID of the File Rules above and store them in the $RulesRefs variable
                            $i = 1
                            $RulesRefs = @()
                            $imax = ($KernelProtectedHashesBlockResults).count
                            while ($i -le $imax) {
                                $KernelProtectedHashesBlockResults | ForEach-Object { 
                                    $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AA_$i`" />"
                                    $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AB_$i`" />"
                                    $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AC_$i`" />"
                                    $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AD_$i`" />"
                                    $i++
                                }
                            }  
                            # Save the File Rules and File Rule Refs in the FileRulesAndFileRefs.txt in the current working directory for debugging purposes
                            $Rules + $RulesRefs | Out-File KernelProtectedFiles.txt                    
                            # Put the Rules and RulesRefs in an empty policy file
                            New-EmptyPolicy -RulesContent $Rules -RuleRefsContent $RulesRefs | Out-File .\KernelProtectedFiles.xml                
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
                }

                # Exit the operation if user didn't select any folder paths
                else {                                      
                    Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Red
                    # Re-Deploy Basepolicy in Enforced mode
                    Update-BasePolicyToEnforced 
                    break
                }

                if (-NOT $Debug) {
                    Remove-Item -Path ".\FileRulesAndFileRefs.txt" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\DeletedFileHashesEventsPolicy.xml" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force  -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\RulesForFilesNotInUserSelectedPaths.xml" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\KernelProtectedFiles.xml" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\KernelProtectedFiles.txt" -Force -ErrorAction SilentlyContinue
                }

                # Re-Deploy Basepolicy in Enforced mode
                Update-BasePolicyToEnforced         

                #################### Supplemental-policy-processing-and-deployment ############################
                
                $SuppPolicyPath = ".\SupplementalPolicy$SuppPolicyName.xml" 
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "Supplemental Policy $SuppPolicyName made on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)
                Add-SignerRule -FilePath $SuppPolicyPath -CertificatePath $CertPath -Update -User -Kernel

                # Make sure policy rule options that don't belong to a Supplemental policy don't exit
                @(0, 1, 2, 3, 4, 6, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }
     
                Set-HVCIOptions -Strict -FilePath $SuppPolicyPath             
                Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version "1.0.0.0"            

                ConvertFrom-CIPolicy $SuppPolicyPath "$SuppPolicyID.cip" | Out-Null
                
                # Configure the parameter splat
                $ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$SuppPolicyID.cip"
                    'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                }
                # Sign the files with the specified cert
                Start-Process @ProcessParams
            
                Remove-Item ".\$SuppPolicyID.cip" -Force            
                Rename-Item "$SuppPolicyID.cip.p7" -NewName "$SuppPolicyID.cip" -Force
                CiTool --update-policy ".\$SuppPolicyID.cip" -json
                Remove-Item ".\$SuppPolicyID.cip" -Force
            
                Write-host "`nSupplemental policy with the following details has been Signed and Deployed in Enforced Mode.`n" -ForegroundColor Green
                # create an object to display on the console
                [PSCustomObject]@{
                    SupplementalPolicyName = $SuppPolicyName
                    SupplementalPolicyGUID = $SuppPolicyID
                }             
            } 
        }

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
                Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete        
                Set-RuleOption -FilePath $PolicyPath -Option 3
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null
                
                # Configure the parameter splat
                $ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$PolicyID.cip"
                    'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                }
                # Sign the files with the specified cert
                Start-Process @ProcessParams
            
                Remove-Item ".\$PolicyID.cip" -Force         
                Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force            
                Write-host "`n`nThe Base policy with the following details has been Re-Signed and Re-Deployed in Audit Mode:" -ForegroundColor Green        
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

                    # Scan each of the folder paths that user selected
                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {

                        # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
                        [System.Collections.Hashtable]$UserInputProgramFoldersPolicyMakerHashTable = @{
                            FilePath             = ".\ProgramDir_ScanResults$($i).xml"
                            ScanPath             = $ProgramsPaths[$i]
                            Level                = $Level
                            Fallback             = $Fallbacks ? (Get-Fallbacks -Fallbacks $Fallbacks) : 'Hash'
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
                
                    #Re-Deploy-Basepolicy-in-Enforced-mode
                    Update-BasePolicyToEnforced       
    
                    Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force 
    
                    #Supplemental-policy-processing-and-deployment
        
                    $SuppPolicyPath = ".\SupplementalPolicy$SuppPolicyName.xml" 
                    $SuppPolicyID = Set-CIPolicyIdInfo -FilePath $SuppPolicyPath -PolicyName "Supplemental Policy $SuppPolicyName made on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath
                    $SuppPolicyID = $SuppPolicyID.Substring(11)
                    Add-SignerRule -FilePath $SuppPolicyPath -CertificatePath $CertPath -Update -User -Kernel
    
                    # Make sure policy rule options that don't belong to a Supplemental policy don't exit
                    @(0, 1, 2, 3, 4, 6, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $SuppPolicyPath -Option $_ -Delete }
     
                    Set-HVCIOptions -Strict -FilePath $SuppPolicyPath             
                    Set-CIPolicyVersion -FilePath $SuppPolicyPath -Version "1.0.0.0"            
    
                    ConvertFrom-CIPolicy $SuppPolicyPath "$SuppPolicyID.cip" | Out-Null 
                    
                    # Configure the parameter splat
                    $ProcessParams = @{
                        'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$SuppPolicyID.cip"
                        'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))
                        'NoNewWindow'  = $true
                        'Wait'         = $true
                    }
                    # Sign the files with the specified cert
                    Start-Process @ProcessParams
            
                    Remove-Item ".\$SuppPolicyID.cip" -Force            
                    Rename-Item "$SuppPolicyID.cip.p7" -NewName "$SuppPolicyID.cip" -Force
                    CiTool --update-policy ".\$SuppPolicyID.cip" -json
                    Remove-Item ".\$SuppPolicyID.cip" -Force

                    Write-host "`nSupplemental policy with the following details has been Signed and Deployed in Enforced Mode.`n" -ForegroundColor Green
                                
                    [PSCustomObject]@{
                        SupplementalPolicyName = $SuppPolicyName
                        SupplementalPolicyGUID = $SuppPolicyID
                    }

                }            
                # Do this if no program path(s) was selected by user
                else {
                    Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Red
                    #Re-Deploy Basepolicy in Enforced mode
                    Update-BasePolicyToEnforced              
                    break
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
                    citool --remove-policy $SupplementalPolicyID -json | Out-Null
                    # remove the old policy files unless user chose to keep them
                    if (!$KeepOldSupplementalPolicies) { Remove-Item -Path $SuppPolicyPath -Force }            
                }        
                # Prepare the final merged Supplemental policy for deployment    
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath "$SuppPolicyName.xml" -ResetPolicyID -PolicyName "$SuppPolicyName Merged on $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)                  
                Add-SignerRule -FilePath "$SuppPolicyName.xml" -CertificatePath $CertPath -Update -User -Kernel
                Set-HVCIOptions -Strict -FilePath "$SuppPolicyName.xml"
                Set-RuleOption -FilePath "$SuppPolicyName.xml" -Option 6 -Delete
                ConvertFrom-CIPolicy "$SuppPolicyName.xml" "$SuppPolicyID.cip" | Out-Null
                
                # Configure the parameter splat
                $ProcessParams = @{
                    'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$SuppPolicyID.cip"
                    'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))
                    'NoNewWindow'  = $true
                    'Wait'         = $true
                }
                # Sign the files with the specified cert
                Start-Process @ProcessParams
            
                Remove-Item ".\$SuppPolicyID.cip" -Force            
                Rename-Item "$SuppPolicyID.cip.p7" -NewName "$SuppPolicyID.cip" -Force
                CiTool --update-policy "$SuppPolicyID.cip" -json
                Remove-Item -Path "$SuppPolicyID.cip" -Force
                Write-Host "`nThe Signed Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones, please restart your system." -ForegroundColor Green                       
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
                    @(0, 2, 5, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 6, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete } 
                }
                "Lightly_Managed_system_Policy" {                                          
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
                    Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Signed And Reputable policy refreshed on $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 6, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }            
                    # Configure required services for ISG authorization
                    Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -Wait -NoNewWindow
                    Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', "start= auto" -Wait -NoNewWindow
                }
                "DefaultWindows_WithBlockRules" {                                            
                    Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml" -Destination ".\DefaultWindows_Enforced.xml"
                   
                    # Allowing SignTool to be able to run after Default Windows base policy is deployed
                    Write-Host "`nCreating allow rules for SignTool.exe in the DefaultWindows base policy so you can continue using it after deploying the DefaultWindows base policy." -ForegroundColor Blue
                    New-Item -Path "$env:TEMP\TemporarySignToolFile" -ItemType Directory -Force | Out-Null
                    Copy-Item -Path $($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool)) -Destination "$env:TEMP\TemporarySignToolFile" -Force
                    New-CIPolicy -ScanPath "$env:TEMP\TemporarySignToolFile" -Level FilePublisher -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\SignTool.xml
                    # Delete the Temporary folder in the TEMP folder
                    Remove-Item -Recurse -Path "$env:TEMP\TemporarySignToolFile" -Force
                                            
                    # Scan PowerShell core directory and add them to the Default Windows base policy so that the module can be used after it's been deployed
                    if (Test-Path "C:\Program Files\PowerShell") {
                        Write-Host "`nCreating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it." -ForegroundColor Blue                    
                        New-CIPolicy -ScanPath "C:\Program Files\PowerShell" -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml                        
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, .\SignTool.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }
                    else {
                        Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\SignTool.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\BasePolicy.xml | Out-Null
                    }      
                    Set-CIPolicyIdInfo -FilePath .\BasePolicy.xml -PolicyName "Default Windows Plus Block Rules refreshed On $(Get-Date -Format 'MM-dd-yyyy')"
                    @(0, 2, 5, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ }
                    @(3, 4, 6, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\BasePolicy.xml -Option $_ -Delete }
                }
            }
    
            if ($UpdateBasePolicy -and $RequireEVSigners) { Set-RuleOption -FilePath .\BasePolicy.xml -Option 8 }   
            
            # Remove the extra files create during module operation that are no longer necessary
            Remove-Item '.\AllowPowerShell.xml' -Force -ErrorAction SilentlyContinue
            Remove-Item '.\DefaultWindows_Enforced.xml' -Force -ErrorAction SilentlyContinue
            Remove-Item '.\AllowMicrosoft.xml' -Force -ErrorAction SilentlyContinue
            Remove-Item '.\Microsoft recommended block rules.xml' -Force     
            Remove-Item '.\SignTool.xml' -Force -ErrorAction SilentlyContinue 

            # Get the policy ID of the currently deployed base policy based on the policy name that user selected
            $CurrentID = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.Friendlyname -eq $CurrentBasePolicyName }).BasePolicyID
            $CurrentID = "{$CurrentID}"
            Remove-Item ".\$CurrentID.cip" -Force -ErrorAction SilentlyContinue

            [xml]$xml = Get-Content ".\BasePolicy.xml"        
            $xml.SiPolicy.PolicyID = $CurrentID
            $xml.SiPolicy.BasePolicyID = $CurrentID
            $xml.Save(".\BasePolicy.xml")

            Add-SignerRule -FilePath .\BasePolicy.xml -CertificatePath $CertPath -Update -User -Kernel -Supplemental

            Set-CIPolicyVersion -FilePath .\BasePolicy.xml -Version "1.0.0.1"
            Set-HVCIOptions -Strict -FilePath .\BasePolicy.xml

            ConvertFrom-CIPolicy ".\BasePolicy.xml" "$CurrentID.cip" | Out-Null                       

            # Configure the parameter splat
            $ProcessParams = @{
                'ArgumentList' = 'sign', '/v' , '/n', "`"$CertCN`"", '/p7', '.', '/p7co', '1.3.6.1.4.1.311.79.1', '/fd', 'certHash', ".\$CurrentID.cip"
                'FilePath'     = ($SignToolPath ? (Get-SignTool -SignToolExePath $SignToolPath) : (Get-SignTool))
                'NoNewWindow'  = $true
                'Wait'         = $true
            }
            # Sign the files with the specified cert
            Start-Process @ProcessParams

            Remove-Item ".\$CurrentID.cip" -Force            
            Rename-Item "$CurrentID.cip.p7" -NewName "$CurrentID.cip" -Force  
            # Deploy the new base policy with the same GUID on the system
            CiTool --update-policy "$CurrentID.cip" -json
            # Remove the policy binary after it's been deployed
            Remove-Item ".\$CurrentID.cip" -Force

            # Keep the new base policy XML file that was just deployed, in the current directory, so user can keep it for later
            switch ($NewBasePolicyType) {
                "AllowMicrosoft_Plus_Block_Rules" {
                    Remove-Item "AllowMicrosoftPlusBlockRules.xml" -Force -ErrorAction SilentlyContinue
                    Rename-Item -Path ".\BasePolicy.xml" -NewName "AllowMicrosoftPlusBlockRules.xml" 
                }
                "Lightly_Managed_system_Policy" {
                    Remove-Item "SignedAndReputable.xml" -Force -ErrorAction SilentlyContinue
                    Rename-Item -Path ".\BasePolicy.xml" -NewName "SignedAndReputable.xml"
                }
                "DefaultWindows_WithBlockRules" {
                    Remove-Item "DefaultWindowsPlusBlockRules.xml" -Force -ErrorAction SilentlyContinue
                    Rename-Item -Path ".\BasePolicy.xml" -NewName "DefaultWindowsPlusBlockRules.xml" 
                }
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

.COMPONENT
Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
Using official Microsoft methods, Edits Signed WDAC policies deployed on the system (Windows Defender Application Control)

.PARAMETER AllowNewAppsAuditEvents
Rebootlessly install new apps/programs when Signed policy is already deployed, use audit events to capture installation files, scan their directories for new Supplemental policy, Sign and deploy thew Supplemental policy.

.PARAMETER AllowNewApps
Rebootlessly install new apps/programs when Signed policy is already deployed, scan their directories for new Supplemental policy, Sign and deploy thew Supplemental policy.

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

.PARAMETER MergeSupplementalPolicies
Merges multiple Signed deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one. System restart needed to take effect.

.PARAMETER UpdateBasePolicy
It can rebootlessly change the type of the deployed signed base policy. It can update the recommended block rules and/or change policy rule options in the deployed base policy.

#>
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete

# argument tab auto-completion for Certificate common name
$ArgumentCompleterCertificateCN = {
     
    $CNs = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Subject.Substring(3) | Where-Object { $_ -NotLike "*, DC=*" } |
    ForEach-Object {
            
        if ($_ -like "*CN=*") {
            
            $_ -match "CN=(?<cn>[^,]+)" | Out-Null
        
            return $Matches['cn']
        }
        else { return $_ }
    }   
    
    $CNs | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Edit-SignedWDACConfig" -ParameterName "CertCN" -ScriptBlock $ArgumentCompleterCertificateCN


# argument tab auto-completion for Policy Paths to show only .xml files and only base policies
$ArgumentCompleterPolicyPaths = {
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | ForEach-Object {
        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq "Base Policy") { $_ }
    } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Edit-SignedWDACConfig" -ParameterName "PolicyPaths" -ScriptBlock $ArgumentCompleterPolicyPaths


# argument tab auto-completion for Certificate Path to show only .cer files
$ArgumentCompleterCertPath = {
    # Note the use of -Depth 1
    # Enclosing the $results = ... assignment in (...) also passes the value through.
    ($results = Get-ChildItem -Depth 2 -Filter *.cer | foreach-object { "`"$_`"" })
    if (-not $results) {
        # No results?
        $null # Dummy response that prevents fallback to the default file-name completion.
    }   
}
Register-ArgumentCompleter -CommandName "Edit-SignedWDACConfig" -ParameterName "CertPath" -ScriptBlock $ArgumentCompleterCertPath


# argument tab auto-completion for Certificate Path to show only .cer files
$ArgumentCompleterSignToolPath = {
    Get-ChildItem | where-object { $_.extension -like '*.exe' } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Edit-SignedWDACConfig" -ParameterName "SignToolPath" -ScriptBlock $ArgumentCompleterSignToolPath


# argument tab auto-completion for Supplemental Policy Paths to show only .xml files and only Supplemental policies
$ArgumentCompleterSuppPolicyPaths = {
    Get-ChildItem | where-object { $_.extension -like '*.xml' } | ForEach-Object {
        $xmlitem = [xml](Get-Content $_)
        $PolicyType = $xmlitem.SiPolicy.PolicyType

        if ($PolicyType -eq "Supplemental Policy") { $_ }
    } | foreach-object { return "`"$_`"" }
}
Register-ArgumentCompleter -CommandName "Edit-SignedWDACConfig" -ParameterName "SuppPolicyPaths" -ScriptBlock $ArgumentCompleterSuppPolicyPaths
