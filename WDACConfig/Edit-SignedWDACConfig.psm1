#requires -version 7.3.3
function Edit-SignedWDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = "set1",
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = "set1", Position = 0, ValueFromPipeline = $true)][switch]$AllowNewApps_AuditEvents,
        [Parameter(Mandatory = $false, ParameterSetName = "set2", Position = 0, ValueFromPipeline = $true)][switch]$AllowNewApps,
        [Parameter(Mandatory = $false, ParameterSetName = "set3", Position = 0, ValueFromPipeline = $true)][switch]$Merge_SupplementalPolicies,        
                 
        [ValidatePattern('.*\.cer')]
        [Parameter(Mandatory = $true, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set2", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set3", ValueFromPipelineByPropertyName = $true)]     
        [string]$CertPath,

        [Parameter(Mandatory = $true, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set2", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set3", ValueFromPipelineByPropertyName = $true)]       
        [string]$SuppPolicyName,        

        [ValidatePattern('.*\.xml')]
        [Parameter(Mandatory = $true, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set2", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set3", ValueFromPipelineByPropertyName = $true)]        
        [string[]]$PolicyPaths,

        [ValidatePattern('.*\.exe')]
        [Parameter(Mandatory = $false, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "set2", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $false, ParameterSetName = "set3", ValueFromPipelineByPropertyName = $true)]
        [string]$SignToolPath,

        [ValidateScript({
                try {
                    # TryCatch to show a custom error message instead of saying input is null when personal store is empty 
                ((Get-ChildItem -ErrorAction Stop -Path 'Cert:\CurrentUser\My').Subject.Substring(3)) -contains $_            
                }
                catch {
                    Write-Error "A certificate with the provided common name doesn't exist in the personal store of the user certificates."
                } # this error msg is shown when cert CN is not available in the personal store of the user certs
            }, ErrorMessage = "A certificate with the provided common name doesn't exist in the personal store of the user certificates." )]
        [Parameter(Mandatory = $true, ParameterSetName = "set1", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set2", ValueFromPipelineByPropertyName = $true)]
        [Parameter(Mandatory = $true, ParameterSetName = "set3", ValueFromPipelineByPropertyName = $true)]
        [string]$CertCN,

        [ValidatePattern('.*\.xml')]
        [Parameter(Mandatory = $true, ParameterSetName = "set3", ValueFromPipelineByPropertyName = $true)]
        [string[]]$SuppPolicyPaths,

        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Debugmode,
        [ValidateRange(1024KB, [int64]::MaxValue)][Parameter(Mandatory = $false, ParameterSetName = "set1")][Int64]$LogSize,
        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )

    begin {

        # Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
        function Update-self {
            $currentversion = (Test-modulemanifest "$psscriptroot\WDACConfig.psd1").Version.ToString()
            try {
                $latestversion = Invoke-RestMethod -Uri "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt"
            }
            catch {
                Write-Error "Couldn't verify if the latest version of the module is installed, please check your Internet connection. You can optionally bypass the online check by using -SkipVersionCheck parameter."
                break
            }
            if (-NOT ($currentversion -eq $latestversion)) {
                Write-Host "The currently installed module's version is $currentversion while the latest version is $latestversion - Auto Updating the module now and will run your command after that 💓"
                Remove-Module -Name WDACConfig -Force
                try {
                    Uninstall-Module -Name WDACConfig -AllVersions -Force -ErrorAction Stop
                    Install-Module -Name WDACConfig -RequiredVersion $latestversion -Force              
                    Import-Module -Name WDACConfig -RequiredVersion $latestversion -Force -Global
                }
                catch {
                    Install-Module -Name WDACConfig -RequiredVersion $latestversion -Force
                    Import-Module -Name WDACConfig -RequiredVersion $latestversion -Force -Global
                }            
            }
        }

        # Test Admin privileges
        Function Test-IsAdmin {
            $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal $identity
            $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        }

        # Increase Code Integrity Operational Event Logs size from the default 1MB to user defined size
        function Set-LogSize {
            [CmdletBinding()]
            param ([int64]$LogSize)        
            $logName = 'Microsoft-Windows-CodeIntegrity/Operational'
            $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
            $log.MaximumSizeInBytes = $LogSize
            $log.IsEnabled = $true
            $log.SaveChanges()
        }

        #Re-Deploy Basepolicy in Enforcement mode
        function Update-BasePolicyToEnforcement {        
            Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete
            Set-RuleOption -FilePath $PolicyPath -Option 3 -Delete
            ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null
            & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$PolicyID.cip"              
            Remove-Item ".\$PolicyID.cip" -Force            
            Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
            CiTool --update-policy ".\$PolicyID.cip" -json
            Remove-Item ".\$PolicyID.cip" -Force
            Write-host "`n`nThe Base policy with the following details has been Re-Signed and Re-Deployed in Enforcement Mode:" -ForegroundColor Green        
            Write-Output "PolicyName = $PolicyName"
            Write-Output "PolicyGUID = $PolicyID`n"
        }

        if (-NOT (Test-IsAdmin)) {
            write-host "Administrator privileges Required" -ForegroundColor Magenta
            break
        }

        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { Update-self }

    }

    process {
                            
        if ($AllowNewApps_AuditEvents) {
            if ($AllowNewApps_AuditEvents -and $LogSize) { Set-LogSize -LogSize $LogSize }
            Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path ".\SupplementalPolicy$SuppPolicyName.xml" -Force -ErrorAction SilentlyContinue
            $Date = Get-Date
            $ProgramDir_ScanResultsArray = @()

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

                if ($SignToolPath) {
                    $SignToolPath = $SignToolPath
                }
                else {
                    if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
                        if ( Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe") {
                            $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe" 
                        }
                        else {
                            Write-Error "signtool.exe couldn't be found"
                            break
                        }
                    }
                    elseif ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
                        if (Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe") {
                            $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe"
                        }
                        else {
                            Write-Error "signtool.exe couldn't be found"
                            break
                        }
                    }           
                }
                & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$PolicyID.cip"              
                Remove-Item ".\$PolicyID.cip" -Force         
                Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force
                Write-host "`n`nThe Base policy with the following details has been Re-Signed and Re-Deployed in Audit Mode:" -ForegroundColor Green        
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID"

                #User Interaction
                Write-host "`nAudit mode deployed, start installing your programs now" -ForegroundColor Magenta        
                Write-Host "When you've finished installing programs, Press Enter to start selecting program directories to scan`n" -ForegroundColor Blue
                Pause

                $ProgramsPaths = @()
                Write-host "`nSelect program directories to scan`n" -ForegroundColor Cyan
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
        
                if (-NOT ($ProgramsPaths.count -eq 0)) {

                    Write-Host "Here are the paths you selected:" -ForegroundColor Yellow
                    $ProgramsPaths | ForEach-Object { $_ }

                    # EventCapturing                   

                    # produce policy xml file from event viewer logs
                    Write-host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan
    
                    # Get Event viewer logs for code integrity
                    $block2 = {
                        foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } | Where-Object { $_.TimeCreated -ge $Date } ) {
                            $xml = [xml]$event.toxml()
                            $xml.event.eventdata.data |
                            ForEach-Object { $hash = @{} } { $hash[$_.name] = $_.'#text' } { [pscustomobject]$hash } |
                            ForEach-Object {
                                $_ | Select-Object FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'                    
                            }
                        }
                    }                
                    $block2results = Invoke-Command -ScriptBlock $block2

                    if ($block2results) {

                        # Create File Rules based on hash of the files and store them in the $Rules variable
                        $i = 1
                        $imax = ($block2results).count
                        while ($i -le $imax) {
                            $block2results | ForEach-Object {  
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AA_$i`" FriendlyName=`"$($_.'File Name') SHA256 Hash`" Hash=`"$($_.'SHA256 Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AB_$i`" FriendlyName=`"$($_.'File Name') SHA256 Flat Hash`" Hash=`"$($_.'SHA256 Flat Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AC_$i`" FriendlyName=`"$($_.'File Name') SHA1 Hash`" Hash=`"$($_.'SHA1 Hash')`" />"
                                $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AD_$i`" FriendlyName=`"$($_.'File Name') SHA1 Flat Hash`" Hash=`"$($_.'SHA1 Flat Hash')`" />"
                                $i++
                            }
                        }
                        # Create File Rule Refs based on the ID of the File Rules above and store them in the $RulesRefs variable
                        $i = 1
                        $imax = ($block2results).count
                        while ($i -le $imax) {
                            $block2results | ForEach-Object { 
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AA_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AB_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AC_$i`" />"
                                $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AD_$i`" />"
                                $i++
                            }
                        }  
                        # Save the the File Rules and File Rule Refs to the Out-File FileRulesAndFileRefs.txt in the current working directory for debugging purposes
                        $Rules + $RulesRefs | Out-File FileRulesAndFileRefs.txt

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
                        $EmptyPolicy | Out-File .\EventsSupplementalPolicy.xml                    
                        # adding the policy file that consists of rules from audit even logs, to the array
                        $ProgramDir_ScanResultsArray += "EventsSupplementalPolicy.xml"
                    }

                    #Process Program Folders From User input
        
                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {
                        New-CIPolicy -FilePath ".\ProgramDir_ScanResults$($i).xml" -ScanPath $ProgramsPaths[$i] -Level SignedVersion -Fallback FilePublisher, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths
                    }            

                    # merge-cipolicy accept arrays - collecting all the policy files created by scanning user specified folders
                    $ProgramDir_ScanResults = Get-ChildItem ".\" | Where-Object { $_.Name -like 'ProgramDir_ScanResults*.xml' }                
                    foreach ($file in $ProgramDir_ScanResults) {
                        $ProgramDir_ScanResultsArray += $file.FullName
                    }             

                    Merge-CIPolicy -PolicyPaths $ProgramDir_ScanResultsArray -OutputFilePath ".\SupplementalPolicy$SuppPolicyName.xml" | Out-Null     
                }

                else {                                      
                    Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Magent
                    # Re-Deploy Basepolicy in Enforcement mode
                    Update-BasePolicyToEnforcement 
                    break
                }

                if (-NOT $Debugmode) {
                    Remove-Item -Path ".\FileRulesAndFileRefs.txt" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path "EventsSupplementalPolicy.xml" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force  -ErrorAction SilentlyContinue
                }

                # Re-Deploy Basepolicy in Enforcement mode
                Update-BasePolicyToEnforcement         

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

                & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$SuppPolicyID.cip"              
                Remove-Item ".\$SuppPolicyID.cip" -Force            
                Rename-Item "$SuppPolicyID.cip.p7" -NewName "$SuppPolicyID.cip" -Force
                CiTool --update-policy ".\$SuppPolicyID.cip" -json
                Remove-Item ".\$SuppPolicyID.cip" -Force
            
                Write-host "`nSupplemental policy with the following details has been Signed and Deployed in Enforcement Mode.`n" -ForegroundColor Green

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
    
            $ProgramDir_ScanResultsArray = @()
    
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
    
                if ($SignToolPath) {
                    $SignToolPath = $SignToolPath
                }
                else {
                    if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
                        if ( Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe") {
                            $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe" 
                        }
                        else {
                            Write-Error "signtool.exe couldn't be found"
                            break
                        }
                    }
                    elseif ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
                        if (Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe") {
                            $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe"
                        }
                        else {
                            Write-Error "signtool.exe couldn't be found"
                            break
                        }
                    }           
                }        
                & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$PolicyID.cip"              
                Remove-Item ".\$PolicyID.cip" -Force         
                Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force            
                Write-host "`n`nThe Base policy with the following details has been Re-Signed and Re-Deployed in Audit Mode:" -ForegroundColor Green        
                Write-Output "PolicyName = $PolicyName"
                Write-Output "PolicyGUID = $PolicyID"
    
                #User Interaction            
                Write-host "`nAudit mode deployed, start installing your programs now" -ForegroundColor Magenta    
                Write-Host "When you've finished installing programs, Press Enter to start selecting program directories to scan`n" -ForegroundColor Blue
                Pause
    
                $ProgramsPaths = @()
                Write-host "`nSelect program directories to scan`n" -ForegroundColor Cyan
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
            
                if (-NOT ($ProgramsPaths.count -eq 0)) {
        
                    Write-Host "Here are the paths you selected:" -ForegroundColor Yellow
                    $ProgramsPaths | ForEach-Object { $_ }
    
                    #Process Program Folders From User input     
                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {
                        New-CIPolicy -FilePath ".\ProgramDir_ScanResults$($i).xml" -ScanPath $ProgramsPaths[$i] -Level SignedVersion -Fallback FilePublisher, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths
                    }            
    
                    # merge-cipolicy accept arrays - collecting all the policy files created by scanning user specified folders
                    $ProgramDir_ScanResults = Get-ChildItem ".\" | Where-Object { $_.Name -like 'ProgramDir_ScanResults*.xml' }                
                    foreach ($file in $ProgramDir_ScanResults) {
                        $ProgramDir_ScanResultsArray += $file.FullName
                    }
    
                    Merge-CIPolicy -PolicyPaths $ProgramDir_ScanResultsArray -OutputFilePath ".\SupplementalPolicy$SuppPolicyName.xml" | Out-Null                                  
                
                    #Re-Deploy-Basepolicy-in-Enforcement-mode
                    Update-BasePolicyToEnforcement       
    
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
    
                    & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$SuppPolicyID.cip"              
                    Remove-Item ".\$SuppPolicyID.cip" -Force            
                    Rename-Item "$SuppPolicyID.cip.p7" -NewName "$SuppPolicyID.cip" -Force
                    CiTool --update-policy ".\$SuppPolicyID.cip" -json
                    Remove-Item ".\$SuppPolicyID.cip" -Force

                    Write-host "`nSupplemental policy with the following details has been Signed and Deployed in Enforcement Mode.`n" -ForegroundColor Green
                                
                    [PSCustomObject]@{
                        SupplementalPolicyName = $SuppPolicyName
                        SupplementalPolicyGUID = $SuppPolicyID
                    }

                }            
                # If no program path was provied
                else {
                    Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Magenta
                    #Re-Deploy Basepolicy in Enforcement mode
                    Update-BasePolicyToEnforcement              
                    break
                }
            } 
        }

        if ($Merge_SupplementalPolicies) {
            foreach ($PolicyPath in $PolicyPaths) {
                # Input policy verification prior to doing anything
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {                                
                    $Supplementalxml = [xml](Get-Content $SuppPolicyPath)
                    $SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID
                    $SupplementalPolicyType = $Supplementalxml.SiPolicy.PolicyType
                    $DeployedPoliciesIDs = (CiTool -lp -json | ConvertFrom-Json).Policies.PolicyID | ForEach-Object { return "{$_}" }         
                    if ($SupplementalPolicyType -ne "Supplemental Policy") {
                        Write-Error "The Selected XML file with GUID $SupplementalPolicyID isn't a Supplemental Policy."
                        break
                    }
                    if ($DeployedPoliciesIDs -notcontains $SupplementalPolicyID) {
                        Write-Error "The Selected Supplemental XML file with GUID $SupplementalPolicyID isn't deployed on the system."
                        break
                    }
                }
                Merge-CIPolicy -PolicyPaths $SuppPolicyPaths -OutputFilePath "$SuppPolicyName.xml" | Out-Null
                foreach ($SuppPolicyPath in $SuppPolicyPaths) {                                
                    $Supplementalxml = [xml](Get-Content $SuppPolicyPath)
                    $SupplementalPolicyID = $Supplementalxml.SiPolicy.PolicyID                         
                    citool --remove-policy $SupplementalPolicyID -json | Out-Null             
                }            
                $SuppPolicyID = Set-CIPolicyIdInfo -FilePath "$SuppPolicyName.xml" -ResetPolicyID -PolicyName "$SuppPolicyName Merged on $(Get-Date -Format 'MM-dd-yyyy')" -BasePolicyToSupplementPath $PolicyPath
                $SuppPolicyID = $SuppPolicyID.Substring(11)                  
                Add-SignerRule -FilePath $SuppPolicyPath -CertificatePath $CertPath -Update -User -Kernel
                Set-HVCIOptions -Strict -FilePath "$SuppPolicyName.xml"
                Set-RuleOption -FilePath $SuppPolicyPath -Option 6 -Delete
                ConvertFrom-CIPolicy "$SuppPolicyName.xml" "$SuppPolicyID.cip" | Out-Null
    
                if ($SignToolPath) {
                    $SignToolPath = $SignToolPath
                }
                else {
                    if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
                        if ( Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe") {
                            $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe" 
                        }
                        else {
                            Write-Error "signtool.exe couldn't be found"
                            break
                        }
                    }
                    elseif ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
                        if (Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe") {
                            $SignToolPath = "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe"
                        }
                        else {
                            Write-Error "signtool.exe couldn't be found"
                            break
                        }
                    }           
                }        
                & $SignToolPath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$SuppPolicyID.cip"              
                Remove-Item ".\$SuppPolicyID.cip" -Force            
                Rename-Item "$SuppPolicyID.cip.p7" -NewName "$SuppPolicyID.cip" -Force
                CiTool --update-policy "$SuppPolicyID.cip" -json
                Write-Host "`nThe Signed Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones, please restart your system." -ForegroundColor Green                       
            } 
        }
    }

    <#
.SYNOPSIS
Edits Signed WDAC policies deployed on the system (Windows Defender Application Control)

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig

.DESCRIPTION
Using official Microsoft methods, Edits Signed WDAC policies deployed on the system (Windows Defender Application Control)

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Using official Microsoft methods, Edits Signed WDAC policies deployed on the system (Windows Defender Application Control)

.PARAMETER AllowNewApps_AuditEvents
Rebootlessly install new apps/programs when Signed policy is already deployed, use audit events to capture installation files, scan their directories for new Supplemental policy, Sign and deploy thew Supplemental policy.

.PARAMETER AllowNewApps
Rebootlessly install new apps/programs when Signed policy is already deployed, scan their directories for new Supplemental policy, Sign and deploy thew Supplemental policy.

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

.PARAMETER Merge_SupplementalPolicies
Merges multiple Signed deployed supplemental policies into 1 single supplemental policy, removes the old ones, deploys the new one. System restart needed to take effect.

#>
}

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete

# argument tab auto-completion for Certificate common name
$ArgumentCompleterCertificateCN = {

    $var = certutil -asn $CertPath

    $cnFound = $false
    $count = 0
    foreach ($line in $var -split "`n") {
        if ($line -match '\(cn\)') {
            if ($count -eq 0) {
                $count++
            }
            elseif ($count -eq 1) {
                $cnFound = $true
            }
            continue
        }
        if ($cnFound -and $line -match '"(.+)"') {
            $regexString = $matches[1]
            break
        }
    }                

    $CertStoreResults = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Subject.Substring(3)
    foreach ($item in $CertStoreResults) {
        if ($item -eq $regexString) {
            $finalResult = $item 
        }
    }
    if (-NOT $finalResult) {
        $finalResult = (Get-ChildItem -Path 'Cert:\CurrentUser\My').Subject.Substring(3) | Where-Object { $_ -NotLike "*, DC=*" }
    }
    return "`"$finalResult`""
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
    Get-ChildItem | where-object { $_.extension -like '*.cer' } | foreach-object { return "`"$_`"" }   
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
