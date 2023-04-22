#requires -version 7.3.3
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

        [ValidateRange(1024KB, [int64]::MaxValue)]
        [Parameter(Mandatory = $false, ParameterSetName = "Allow New Apps Audit Events")]
        [Int64]$LogSize,

        [ValidateSet([BasePolicyNamez])]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")][string[]]$CurrentBasePolicyName,

        [ValidateSet("AllowMicrosoft_Plus_Block_Rules", "Lightly_Managed_system_Policy", "DefaultWindows_WithBlockRules")]
        [Parameter(Mandatory = $true, ParameterSetName = "Update Base Policy")][string]$NewBasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = "Update Base Policy")][switch]$RequireEVSigners,

        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )

    begin {

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

        if (-NOT (Test-IsAdmin)) {
            write-host "Administrator privileges Required" -ForegroundColor Magenta
            break
        }

        $ErrorActionPreference = 'Stop'         
        if (-NOT $SkipVersionCheck) { Update-self }
       
    }

    process {
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
                Set-RuleOption -FilePath $PolicyPath -Option 3
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force            
                Write-host "`n`nThe Base policy with the following details has been Re-Deployed in Audit Mode:" -ForegroundColor Green        
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

                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {
                        New-CIPolicy -FilePath ".\ProgramDir_ScanResults$($i).xml" -ScanPath $ProgramsPaths[$i] -Level $AssignedLevels -Fallback $AssignedFallbacks -UserPEs -MultiplePolicyFormat -UserWriteablePaths
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
                # If no program path was provied
                else {
                    Write-Host "`nNo program folder was selected, reverting the changes and quitting...`n" -ForegroundColor Magenta
                    #Re-Deploy-Basepolicy-in-Enforcement-mode
                    Update-BasePolicyToEnforcement                 
                    break
                }
            }
        }

        if ($AllowNewAppsAuditEvents) {
            if ($AllowNewAppsAuditEvents -and $LogSize) { Set-LogSize -LogSize $LogSize }
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
       
                Set-RuleOption -FilePath $PolicyPath -Option 3
                ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip" | Out-Null            
                CiTool --update-policy ".\$PolicyID.cip" -json
                Remove-Item ".\$PolicyID.cip" -Force
                Write-host "`n`nThe Base policy with the following details has been Re-Deployed in Audit Mode:" -ForegroundColor Green        
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
                    # since New-CIPolicy -Audit doesn't support specifying a time frame for Audit event logs scan, we have to rely on Hash
                    # of the files included in each audit log to create a supplemental policy and can't use any other levels of fallbacks
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
        
                    for ($i = 0; $i -lt $ProgramsPaths.Count; $i++) {
                        New-CIPolicy -FilePath ".\ProgramDir_ScanResults$($i).xml" -ScanPath $ProgramsPaths[$i] -Level $AssignedLevels -Fallback $AssignedFallbacks -UserPEs -MultiplePolicyFormat -UserWriteablePaths
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
                    #Re-Deploy-Basepolicy-in-Enforcement-mode
                    Update-BasePolicyToEnforcement
                    break
                }

                if (-NOT $Debugmode) {
                    Remove-Item -Path ".\FileRulesAndFileRefs.txt" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path "EventsSupplementalPolicy.xml" -Force -ErrorAction SilentlyContinue
                    Remove-Item -Path ".\ProgramDir_ScanResults*.xml" -Force  -ErrorAction SilentlyContinue
                }

                #Re-Deploy-Basepolicy-in-Enforcement-mode
                Update-BasePolicyToEnforcement  

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
        }

        if ($MergeSupplementalPolicies) {        
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
                Set-HVCIOptions -Strict -FilePath "$SuppPolicyName.xml" 
                ConvertFrom-CIPolicy "$SuppPolicyName.xml" "$SuppPolicyID.cip" | Out-Null
                CiTool --update-policy "$SuppPolicyID.cip" -json
                Write-Host "`nThe Supplemental policy $SuppPolicyName has been deployed on the system, replacing the old ones, please restart your system." -ForegroundColor Green
            }
        }

        if ($UpdateBasePolicy) {     

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
            
            Remove-Item .\AllowPowerShell.xml -Force -ErrorAction SilentlyContinue
            Remove-Item .\DefaultWindows_Enforced.xml -Force -ErrorAction SilentlyContinue
            Remove-Item .\AllowMicrosoft.xml -Force -ErrorAction SilentlyContinue
            Remove-Item '.\Microsoft recommended block rules.xml' -Force

            $CurrentID = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" } | Where-Object { $_.Friendlyname -eq $CurrentBasePolicyName }).BasePolicyID
            $CurrentID = "{$CurrentID}"
            [xml]$xml = Get-Content ".\BasePolicy.xml"        
            $xml.SiPolicy.PolicyID = $CurrentID
            $xml.SiPolicy.BasePolicyID = $CurrentID
            $xml.Save(".\BasePolicy.xml")
            ConvertFrom-CIPolicy ".\BasePolicy.xml" "$CurrentID.cip" | Out-Null
            CiTool --update-policy "$CurrentID.cip" -json
            Remove-Item "$CurrentID.cip" -Force
            
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
