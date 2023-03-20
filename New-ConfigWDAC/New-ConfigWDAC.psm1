#requires -version 7.3.3
function New-ConfigWDAC {
    [CmdletBinding(
        DefaultParameterSetName = "set1",
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Module",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = "set1", Position = 0)][switch]$Get_RecommendedBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set9", Position = 0)][switch]$Get_RecommendedDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set7", Position = 0)][switch]$Make_AllowMSFT_WithReccBlockRules,  
        [Parameter(Mandatory = $false, ParameterSetName = "set10", Position = 0)][switch]$Deploy_LatestDriverBlockRules,                                                                                       
        [Parameter(Mandatory = $false, ParameterSetName = "set11", Position = 0)][switch]$Make_ScheduledTask_AutoUpdate_DriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set12", Position = 0)][switch]$Make_PolicyFromAuditLogs,
        [Parameter(Mandatory = $false, ParameterSetName = "set13", Position = 0)][switch]$Prep_SystemFor_MSFTOnlyAudit,        
        [Parameter(Mandatory = $false, ParameterSetName = "set8", Position = 0)][switch]$Make_LightlyManagedPolicy,
        [Parameter(Mandatory = $false, ParameterSetName = "set14", Position = 0)][switch]$ListActivePolicies,
        [Parameter(Mandatory = $false, ParameterSetName = "set15", Position = 0)][switch]$VerifyWDACStatus,
        [Parameter(Mandatory = $false, ParameterSetName = "set2", Position = 0)][switch]$Sign_Deploy_Policy,
        [Parameter(Mandatory = $false, ParameterSetName = "set3", Position = 0)][switch]$Make_SupplementalPolicy,
        [Parameter(Mandatory = $false, ParameterSetName = "set4", Position = 0)][switch]$RemoveSignedPolicy,   
        [Parameter(Mandatory = $false, ParameterSetName = "set5", Position = 0)][switch]$AfterRebootRemoval,
        [Parameter(Mandatory = $false, ParameterSetName = "set6", Position = 0)][switch]$RemoveUNsignedPolicy,  
            
        [parameter(Mandatory = $true, ParameterSetName = "set2", ValueFromPipeline = $true)][string]$CertPath,
        
        [parameter(Mandatory = $true, ParameterSetName = "set3", ValueFromPipeline = $true)][string]$ScanLocation,
        [parameter(Mandatory = $true, ParameterSetName = "set3")][string]$SuppPolicyName,

        [Parameter(Mandatory = $false, ParameterSetName = "set12")]
        [Parameter(Mandatory = $false, ParameterSetName = "set8")]
        [Parameter(Mandatory = $false, ParameterSetName = "set7")]
        [parameter(Mandatory = $false, ParameterSetName = "set3")]
        [switch]$Deployit,

        [parameter(Mandatory = $true, ParameterSetName = "set2", ValueFromPipeline = $true)]
        [parameter(Mandatory = $true, ParameterSetName = "set3", ValueFromPipeline = $true)]
        [parameter(Mandatory = $true, ParameterSetName = "set4", ValueFromPipeline = $true)]
        [parameter(Mandatory = $true, ParameterSetName = "set5", ValueFromPipeline = $true)]
        [string[]]$PolicyPaths,
        [parameter(Mandatory = $false, ParameterSetName = "set2", ValueFromPipeline = $true)]
        [parameter(Mandatory = $false, ParameterSetName = "set4", ValueFromPipeline = $true)]
        [string]$SignToolPath,
        [parameter(Mandatory = $true, ParameterSetName = "set2", ValueFromPipeline = $true)]
        [parameter(Mandatory = $true, ParameterSetName = "set4", ValueFromPipeline = $true)]
        [string]$CertCN,
        
        [parameter(Mandatory = $false, ParameterSetName = "set6")][string[]]$PolicyIDs,

        [ValidateSet([PolicyNamez])]
        [parameter(Mandatory = $false, ParameterSetName = "set6")]
        [string[]]$PolicyNames,

        [Parameter(Mandatory = $false, ParameterSetName = "set8")]
        [Parameter(Mandatory = $false, ParameterSetName = "set12")]
        [Parameter(Mandatory = $false, ParameterSetName = "set7")]
        [switch]$TestMode,
        
        [Parameter(Mandatory = $false, ParameterSetName = "set8")]
        [Parameter(Mandatory = $false, ParameterSetName = "set12")]
        [Parameter(Mandatory = $false, ParameterSetName = "set7")]
        [switch]$RequireEVSigners
    )

    $ErrorActionPreference = 'Stop'    

    # argument tab auto-completion for Policy names 
    Class PolicyNamez : System.Management.Automation.IValidateSetValuesGenerator {
        [string[]] GetValidValues() {
            $PolicyNamez = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).Friendlyname
           
            return [string[]]$PolicyNamez
        }
    }
    
    #region Script-Blocks    
    $Get_RecommendedBlockRulesSCRIPTBLOCK = {             
        $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md"
        $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)" | Out-Null
        $Rules = $Matches[0]
    
        $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_1"\sFriendlyName="Allow\sKernel\sDrivers"\sFileName="\*".*/>', ''
        $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_2"\sFriendlyName="Allow\sUser\smode\scomponents"\sFileName="\*".*/>', ''
        $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_1".*/>', ''
        $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_2".*/>', ''

        $Rules | Out-File '.\Microsoft recommended block rules TEMP.XML'

        Get-Content '.\Microsoft recommended block rules TEMP.XML' | Where-Object { $_.trim() -ne "" } | Out-File '.\Microsoft recommended block rules.XML'

        Remove-Item '.\Microsoft recommended block rules TEMP.XML' -Force
        Set-RuleOption -FilePath '.\Microsoft recommended block rules.XML' -Option 3 -Delete
        Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.XML'
        Write-host "Microsoft recommended block rules.XML policy file has been created in $(Get-Location)" -ForegroundColor Green
    }    
    $Get_RecommendedDriverBlockRulesSCRIPTBLOCK = {       
        $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md"
       
        $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)" | Out-Null
        $DriverRules = $Matches[0]

        $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_1"\sFriendlyName=""\sFileName="\*".*/>', ''
        $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_2"\sFriendlyName=""\sFileName="\*".*/>', ''
        $DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_1".*/>', ''

        # not using this one because then during the merge there will be error - The reason is that "<FileRuleRef RuleID="ID_ALLOW_ALL_2" />" is the only FileruleRef in the XML and after removing it, the <SigningScenario> element will be empty
        #$DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_2".*/>',''
        $DriverRules = $DriverRules -replace '<SigningScenario\sValue="12"\sID="ID_SIGNINGSCENARIO_WINDOWS"\sFriendlyName="Auto\sgenerated\spolicy[\S\s]*<\/SigningScenario>', ''

        $DriverRules | Out-File '.\Microsoft recommended driver block rules TEMP.XML'

        Get-Content '.\Microsoft recommended driver block rules TEMP.XML' | Where-Object { $_.trim() -ne "" } | Out-File '.\Microsoft recommended driver block rules.XML'
        Remove-Item '.\Microsoft recommended driver block rules TEMP.XML' -Force
        Set-RuleOption -FilePath '.\Microsoft recommended driver block rules.XML' -Option 3 -Delete
        Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended driver block rules.XML'
        Write-host "Microsoft recommended driver block rules.XML policy file has been created in $(Get-Location)" -ForegroundColor Green
    }
    $Make_AllowMSFT_WithReccBlockRulesSCRIPTBLOCK = {
        Invoke-Command -ScriptBlock $Get_RecommendedBlockRulesSCRIPTBLOCK                              
        Copy-Item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"

        Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.XML' -OutputFilePath .\AllowMicrosoftPlusBlockRules.XML
        
        $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoftPlusBlockRules.XML -ResetPolicyID
        $PolicyID = $PolicyID.Substring(11)        
        Set-CIPolicyIdInfo -PolicyName "DefaultAllowMicrosoft Plus ReccommendedBlockRules Made On $(Get-Date -Format 'MM-dd-yyyy')" -FilePath .\AllowMicrosoftPlusBlockRules.XML

        @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.XML -Option $_ }
        @(3, 9, 10) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.XML -Option $_ -Delete }
        
        if ($TestMode) {
            & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting ".\AllowMicrosoftPlusBlockRules.XML"
        }
        if ($RequireEVSigners) {
            & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners ".\AllowMicrosoftPlusBlockRules.XML"
        }

        Set-HVCIOptions -Strict -FilePath .\AllowMicrosoftPlusBlockRules.XML
        ConvertFrom-CIPolicy .\AllowMicrosoftPlusBlockRules.XML "$PolicyID.cip"

        Remove-Item .\AllowMicrosoft.xml -Force
        Remove-Item '.\Microsoft recommended block rules.XML' -Force
        Write-host -NoNewline "AllowMicrosoftPlusBlockRules.XML policy with GUID" -ForegroundColor Green; Write-host -NoNewline " $PolicyID" -ForegroundColor Magenta; Write-host " has been created." -ForegroundColor Green
        
        if ($Deployit) {
            copy-Item -Path "$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
            Write-host "AllowMicrosoftPlusBlockRules.XML policy has been deployed and its GUID is $PolicyID" -ForegroundColor Cyan
        } 
    }   
    $Deploy_LatestDriverBlockRulesSCRIPTBLOCK = {        
        Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip      
        Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force
        Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force
        Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity"
        citool --refresh -json
        Remove-Item .\VulnerableDriverBlockList -Recurse -Force
        Remove-Item .\VulnerableDriverBlockList.zip -Force
    }    
    $Make_ScheduledTask_AutoUpdate_DriverBlockRulesSCRIPTBLOCK = {
        # create a scheduled task that runs every 7 days
        if (-NOT (Get-ScheduledTask -TaskName "MSFT Driver Block list update" -ErrorAction SilentlyContinue)) {        
            $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit};Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'    
            $TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $env:USERNAME -RunLevel Highest
            # trigger
            $Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7) 
            # register the task
            Register-ScheduledTask -Action $action -Trigger $Time -Principal $TaskPrincipal -TaskPath "MSFT Driver Block list update" -TaskName "MSFT Driver Block list update" -Description "Microsoft Recommended Driver Block List update"
            # define advanced settings for the task
            $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
            # add advanced settings we defined to the task
            Set-ScheduledTask -TaskPath "MSFT Driver Block list update" -TaskName "MSFT Driver Block list update" -Settings $TaskSettings 
        }
    }
    $Make_PolicyFromAuditLogsSCRIPTBLOCK = {        
        # Make sure there is no lingering variable from previous runs - prevent the outfile from getting duplicate rules/ruleRefs if user run this script multiple times
        Remove-Variable * -ErrorAction SilentlyContinue
        # Create a working directory in user's folder
        new-item -Type Directory -Path "$home\WDAC" -Force | Out-Null
        Set-Location "$home\WDAC"
        # Take the AllowMicrosoft.xml policy file from Windows folder and use it as the base policy - reset its policy ID
        Copy-Item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\AllowMicrosoft.xml
        $BasePolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
        $BasePolicyID = $BasePolicyID.Substring(11)
        # define the location of the base policy
        $BasePolicy = "$home\WDAC\AllowMicrosoft.xml"
        # produce policy XML file from event viewer logs
        Write-host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan
        New-CIPolicy -FilePath .\WDAC_From_AuditEvents.xml -Audit -Level SignedVersion -Fallback FilePublisher, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths -WarningAction SilentlyContinue

        # List every \Device\Harddiskvolume - Needed to resolve the file pathes to detect which files in even Event viewer logs are no longer present on the disk - https://superuser.com/questions/1058217/list-every-device-harddiskvolume
        $ScriptBlock = {
            $signature = @'
[DllImport("kernel32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool GetVolumePathNamesForVolumeNameW([MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
[MarshalAs(UnmanagedType.LPWStr)] [Out] StringBuilder lpszVolumeNamePaths, uint cchBuferLength, 
ref UInt32 lpcchReturnLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr FindFirstVolume([Out] StringBuilder lpszVolumeName,
uint cchBufferLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FindNextVolume(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

'@;
            Add-Type -MemberDefinition $signature -Name Win32Utils -Namespace PInvoke -Using PInvoke, System.Text;

            [UInt32] $lpcchReturnLength = 0;
            [UInt32] $Max = 65535
            $sbVolumeName = New-Object System.Text.StringBuilder($Max, $Max)
            $sbPathName = New-Object System.Text.StringBuilder($Max, $Max)
            $sbMountPoint = New-Object System.Text.StringBuilder($Max, $Max)
            [IntPtr] $volumeHandle = [PInvoke.Win32Utils]::FindFirstVolume($sbVolumeName, $Max)
            do {
                $volume = $sbVolumeName.toString()
                $unused = [PInvoke.Win32Utils]::GetVolumePathNamesForVolumeNameW($volume, $sbMountPoint, $Max, [Ref] $lpcchReturnLength);
                $ReturnLength = [PInvoke.Win32Utils]::QueryDosDevice($volume.Substring(4, $volume.Length - 1 - 4), $sbPathName, [UInt32] $Max);
                if ($ReturnLength) {
                    $DriveMapping = @{
                        DriveLetter = $sbMountPoint.toString()
                        VolumeName  = $volume
                        DevicePath  = $sbPathName.ToString()
                    }

                    Write-Output (New-Object PSObject -Property $DriveMapping)
                }
                else {
                    Write-Output "No mountpoint found for: " + $volume
                } 
            } while ([PInvoke.Win32Utils]::FindNextVolume([IntPtr] $volumeHandle, $sbVolumeName, $Max));

        }
        # using script block here because otherwise this command and the command below wouldn't both output to the console
        $results = Invoke-Command -ScriptBlock $ScriptBlock

        #(resutt | Select-Object DriveLetter, DevicePath | Where-Object { $_.DriveLetter -ne ""}).driveletter
        #($results | Select-Object DriveLetter, DevicePath | Where-Object { $_.DriveLetter -ne ""}).devicepath
        #$results | Select-Object DriveLetter, DevicePath | Where-Object { $_.DriveLetter -ne ""}

        # Get Event viewer logs for code integrity - check the file path of all of the files in the log, resolve them using the command above - show files that are no longer available on the disk
        $block2 = {
            foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 }) {
                $xml = [xml]$event.toxml()
                $xml.event.eventdata.data |
                ForEach-Object { $hash = @{} } { $hash[$_.name] = $_.'#text' } { [pscustomobject]$hash } |
                ForEach-Object {
                    if ($_.'File Name' -match ($pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$')) {
                        $hardDiskVolumeNumber = $Matches[1]
                        $remainingPath = $Matches[2]
                        $getletter = $results | Where-Object { $_.devicepath -eq "\Device\HarddiskVolume$hardDiskVolumeNumber" }
                        $usablePath = "$($getletter.DriveLetter)$remainingPath"
                        $_.'File Name' = $_.'File Name' -replace $pattern, $usablePath
                    }
                    if (-NOT (Test-Path $_.'File Name')) {
                        $_ | Select-Object FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                    }
                }
            }
        }
        # using script block here because otherwise this command and the command above wouldn't both output to the console
        $block2results = Invoke-Command -ScriptBlock $block2

        # run the following only if there are any event logs for files no longer on the disk
        if ($block2results) {

            # Create File Rules based on hash of the files no longer available on the disk and store them in the $Rules variable
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
            # Save the the File Rules and File Rule Refs to the Out-File FileRulesAndFileRefs.txt in the current working directory
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

            $EmptyPolicy | Out-File .\DeletedFilesHashes.XML

            # Merge the policy file we created at first using Event Viewer logs, with the policy file we created for Hash of the files no longer available on the disk
            Merge-CIPolicy -PolicyPaths .\WDAC_From_AuditEvents.xml, .\DeletedFilesHashes.XML -OutputFilePath .\SupplementalPolicy.xml
        }
        # do this only if there are no event logs detected with files no longer on the disk, so we use the policy file creater earlier using Audit even logs
        else {
            Rename-Item .\WDAC_From_AuditEvents.xml -NewName "SupplementalPolicy.xml" -Force
        }

        $xml = [xml](Get-Content ".\SupplementalPolicy.xml")
        $PolicyID = $xml.SiPolicy.PolicyID
        Write-host "This is the GUID of the Supplemental Policy: $PolicyID" -ForegroundColor Cyan
        # Convert the SupplementalPolicy.XML policy file from base policy to supplemental policy of our base policy
        Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy.xml" -BasePolicyToSupplementPath $BasePolicy
        Set-CIPolicyIdInfo -PolicyName "Supplemental Policy made from Audit Event Logs on $(Get-Date -Format 'MM-dd-yyyy')" -FilePath ".\SupplementalPolicy.xml"

        # Set the base policy rule options 
        @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $BasePolicy -Option $_ }
        @(3, 4, 9, 10, 13, 14, 15, 18) | ForEach-Object { Set-RuleOption -FilePath $BasePolicy -Option $_ -Delete }

        if ($TestMode) {
            & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting $BasePolicy
        }
        if ($RequireEVSigners) {
            & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners $BasePolicy
        }

        # Set the Supplemental policy rule options
        @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath ".\SupplementalPolicy.xml" -Option $_ -Delete }

        # Set the hypervisor Code Integrity option for Base and Supplemental policies to Strict
        Set-HVCIOptions -Strict -FilePath $BasePolicy 
        Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy.xml"

        # convert the Supplemental Policy file to .cip binary file
        ConvertFrom-CIPolicy ".\SupplementalPolicy.xml" "$policyID.cip"

        # convert the Base policy file to .cip binary file
        Write-host "`nThis is the GUID of the Base Policy: $BasePolicyID" -ForegroundColor Cyan
        ConvertFrom-CIPolicy .\AllowMicrosoft.xml "$BasePolicyID.cip"

        if ($Deployit) {
            Copy-Item -Path "$BasePolicyID.cip", "$policyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" -Force                          
            
            $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq "Prep_SystemFor_MSFTOnlyAudit" }).PolicyID
            CiTool --remove-policy "{$IDToRemove}"
            Write-host "System restart required to activate the deployed policies and to remove the Audit mode Prep policy" -ForegroundColor Green                       
        }
        else {
            do {
                $RemovalQuestion = $(Write-host "`nRemove the Audit mode MicrosoftOnly policy deployed during the prep phase? Enter 1 for Yes, 2 for No." -ForegroundColor Cyan; Read-Host)     
                if ($RemovalQuestion -eq "1" ) {
                    $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq "Prep_SystemFor_MSFTOnlyAudit" }).PolicyID
                    CiTool --remove-policy "{$IDToRemove}"
                    Write-host "System restart required to finish removing the Audit mode Prep policy" -ForegroundColor Green                   
                }
                if ($RemovalQuestion -eq "2" ) {
                    Write-host "Skipping" -ForegroundColor Yellow
                }         
            }                  
            until ($RemovalQuestion -eq "1" -or $RemovalQuestion -eq "2")
        }       
    }
    $Prep_SystemFor_MSFTOnlyAuditSCRIPTBLOCK = {
        Copy-Item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\AllowMicrosoft.xml
        Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option 3
        $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
        $PolicyID = $PolicyID.Substring(11)
        Set-CIPolicyIdInfo -PolicyName "Prep_SystemFor_MSFTOnlyAudit" -FilePath .\AllowMicrosoft.xml
        ConvertFrom-CIPolicy .\AllowMicrosoft.xml "$PolicyID.cip"
        Move-Item -Path "$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
        Write-host "The default AllowMicrosoft policy has been deployed in Audit mode. Restart the system." -ForegroundColor Magenta
    }
    $Make_LightlyManagedPolicySCRIPTBLOCK = { 
        copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
       
        Invoke-Command -ScriptBlock $Get_RecommendedBlockRulesSCRIPTBLOCK        
        
        Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.XML' -OutputFilePath .\SignedAndReputable.xml
        
        @(0, 2, 6, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }
        @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ -Delete }           
            
        if ($TestMode) {
            & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting ".\SignedAndReputable.xml"
        }
        if ($RequireEVSigners) {
            & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners ".\SignedAndReputable.xml"
        }

        $BasePolicyID = Set-CiPolicyIdInfo -FilePath .\SignedAndReputable.xml -ResetPolicyID
        $BasePolicyID = $BasePolicyID.Substring(11)
        
        Set-HVCIOptions -Strict -FilePath .\SignedAndReputable.xml

        Set-CIPolicyIdInfo -PolicyName "SignedAndReputable policy deployed on $(Get-Date -Format 'MM-dd-yyyy')" -FilePath .\SignedAndReputable.xml

        Remove-Item .\AllowMicrosoft.xml -Force
        Remove-Item '.\Microsoft recommended block rules.XML' -Force

        Write-host -NoNewline "This is the PolicyID of the SignedAndReputable.xml:" -ForegroundColor Yellow; Write-host " $BasePolicyID" -ForegroundColor Magenta
        
        ConvertFrom-CIPolicy .\SignedAndReputable.xml "$BasePolicyID.cip" | Out-Null

        if ($Deployit) {            
            Copy-Item -Path ".\$BasePolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
            Write-host -NoNewline "SignedAndReputable.xml policy with GUID" -ForegroundColor Green; Write-host -NoNewline " $BasePolicyID" -ForegroundColor Magenta; Write-host " has been deployed." -ForegroundColor Green
            appidtel start
            sc.exe config appidsvc start= auto
        }        
    }
    $Sign_Deploy_PolicySCRIPTBLOCK = {
        foreach ($PolicyPath in $PolicyPaths) {
            $xml = [xml](Get-Content $PolicyPath)
            $PolicyType = $xml.SiPolicy.PolicyType
            if ($PolicyType -eq "Supplemental Policy") {          
                Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel
            }
            else {            
                Add-SignerRule -FilePath $PolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental
            }
            Set-HVCIOptions -Strict -FilePath $PolicyPath
            Set-RuleOption -FilePath $PolicyPath -Option 6 -Delete            
            $PolicyID = $xml.SiPolicy.PolicyID
            ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip"

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
            Copy-Item -Path ".\$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"

            $MountPoint = "C:\EFIMount"
            $EFIDestinationFolder = "$MountPoint\EFI\Microsoft\Boot\CiPolicies\Active"
            $EFIPartition = (Get-Partition | Where-Object IsSystem).AccessPaths[0]
            if (-Not (Test-Path $MountPoint)) { New-Item -Path $MountPoint -Type Directory -Force }
            mountvol $MountPoint $EFIPartition
            if (-Not (Test-Path $EFIDestinationFolder)) { New-Item -Path $EFIDestinationFolder -Type Directory -Force }

            Copy-Item -Path ".\$PolicyID.cip" -Destination $EFIDestinationFolder -Force

            mountvol $MountPoint /D
            Remove-Item "C:\EFIMount" -Recurse -Force
            Write-host "$PolicyID.cip has been Signed and Deployed." -ForegroundColor Green
        }
    }
    $Make_SupplementalPolicySCRIPTBLOCK = {
        foreach ($PolicyPath in $PolicyPaths) {
            New-CIPolicy -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -ScanPath $ScanLocation `
                -Level SignedVersion -Fallback FilePublisher, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths
            $policyID = Set-CiPolicyIdInfo -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -ResetPolicyID
            $policyID = $policyID.Substring(11)
            Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -BasePolicyToSupplementPath $PolicyPath
            @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object {
                Set-RuleOption -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -Option $_ -Delete }        
            Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy$SuppPolicyName.xml"
            Set-CIPolicyIdInfo -PolicyName "$SuppPolicyName" -FilePath ".\SupplementalPolicy$SuppPolicyName.xml"
            ConvertFrom-CIPolicy ".\SupplementalPolicy$SuppPolicyName.xml" "$policyID.cip"
            if ($Deployit) {
                copy-Item -Path "$policyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
                Write-host -NoNewline "$policyID.cip for " -ForegroundColor Green;
                Write-host -NoNewline "$SuppPolicyName" -ForegroundColor Magenta;
                Write-host " has been deployed." -ForegroundColor Green
                Write-host "Policies are being refreshed, no reboot required." -ForegroundColor Yellow
                citool --refresh -json
            }
        }
    }
    $RemoveSignedPolicySCRIPTBLOCK = {
        foreach ($PolicyPath in $PolicyPaths) {
            # sanitize the policy file by removing SupplementalPolicySigners
            $xml = [xml](Get-Content $PolicyPath)
            $SuppSingerIDs = $xml.SiPolicy.SupplementalPolicySigners.SupplementalPolicySigner.SignerId
            if ($SuppSingerIDs) {
                Write-host "$($SuppSingerIDs.count) SupplementalPolicySigners have been found in the policy file, removing them now..." -ForegroundColor Yellow    
                $SuppSingerIDs | ForEach-Object {
                    $PolContent = Get-Content -Raw -Path $PolicyPath        
                    $PolContent -match "<Signer ID=`"$_`"[\S\s]*</Signer>" | Out-Null
                    $PolContent = $PolContent -replace $Matches[0], ""
                    Set-Content -Value $PolContent -Path $PolicyPath
                }
                $PolContent -match "<SupplementalPolicySigners>[\S\s]*</SupplementalPolicySigners>" | Out-Null     
                $PolContent = $PolContent -replace $Matches[0], ""
                Set-Content -Value $PolContent -Path $PolicyPath
            
                # remove empty lines from the entire policy file       
                (Get-Content -Path $PolicyPath) | Where-Object { $_.trim() -ne "" } | set-content -Path $PolicyPath -Force
                Write-host "Policy successfully sanitized and all SupplementalPolicySigners have been removed." -ForegroundColor Green
            }
            else {
                Write-host "`nNo sanitization required because no SupplementalPolicySigners have been found in the policy file." -ForegroundColor Green
            }
                
            Set-RuleOption -FilePath $PolicyPath -Option 6       
            $PolicyID = $xml.SiPolicy.PolicyID
            ConvertFrom-CIPolicy $PolicyPath "$PolicyID.cip"
            
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
            Copy-Item -Path ".\$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active" -Force
                    
            $MountPoint = "C:\EFIMount"
            $EFIDestinationFolder = "$MountPoint\EFI\Microsoft\Boot\CiPolicies\Active"
            $EFIPartition = (Get-Partition | Where-Object IsSystem).AccessPaths[0]
            if (-Not (Test-Path $MountPoint)) { New-Item -Path $MountPoint -Type Directory -Force }
            mountvol $MountPoint $EFIPartition
                    
            Move-Item -Path ".\$PolicyID.cip" -Destination $EFIDestinationFolder -Force            
            mountvol $MountPoint /D            
            Remove-Item "C:\EFIMount" -Recurse -Force
            Write-host "$PolicyID.cip has been Re-signed and Re-deployed in Unsigned mode." -ForegroundColor Green
        }
    }
    $AfterRebootRemovalSCRIPTBLOCK = {        
        foreach ($PolicyPath in $PolicyPaths) {
            $xml = [xml](Get-Content $PolicyPath)
            $PolicyID = $xml.SiPolicy.PolicyID
            Write-host "Please confirm the prompt twice to remove the policy from both WinDir and EFI partition." -ForegroundColor Cyan   
            CiTool --remove-policy $PolicyID
            CiTool --remove-policy $PolicyID
        }
    }
    $ListActivePoliciesSCRIPTBLOCK = {
        Write-host "`nDisplaying non-System WDAC Policies:" -ForegroundColor Cyan
        (CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }
    }
    $VerifyWDACStatusSCRIPTBLOCK = {
        Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object -Property *codeintegrity* | Format-List
        Write-host "2 -> Enforced`n1 -> Audit mode`n0 -> Disabled/Not running`n" -ForegroundColor Cyan
    }
    $RemoveUNsignedPolicySCRIPTBLOCK = {             
        foreach ($ID in $PolicyIDs ) {
            citool --remove-policy "{$ID}"
        }
        foreach ($PolicyName in $PolicyNames) {                    
            $NameID = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq $PolicyName }).PolicyID                                   
            citool --remove-policy "{$NameID}"
        }        
    }
    $TestModeSCRIPTBLOCK = { 
        param($PolicyPathToEnableTesting)
        @(9, 10) | ForEach-Object { Set-RuleOption -FilePath $PolicyPathToEnableTesting -Option $_ }
    }
    $RequireEVSignersSCRIPTBLOCK = {
        param($PolicyPathToEnableEVSigners)
        Set-RuleOption -FilePath $PolicyPathToEnableEVSigners -Option 8
    }

    #endregion Script-Blocks

    #region function-processing
    if ($Get_RecommendedBlockRules) {              
        Invoke-Command -ScriptBlock $Get_RecommendedBlockRulesSCRIPTBLOCK
    }                                
    if ($Get_RecommendedDriverBlockRules) {
        Invoke-Command -ScriptBlock $Get_RecommendedDriverBlockRulesSCRIPTBLOCK
    }   
    if ($Make_AllowMSFT_WithReccBlockRules) {
        Invoke-Command -ScriptBlock $Make_AllowMSFT_WithReccBlockRulesSCRIPTBLOCK
    }
    if ($Deploy_LatestDriverBlockRules) {
        Invoke-Command -ScriptBlock $Deploy_LatestDriverBlockRulesSCRIPTBLOCK
    }                               
    if ($Make_ScheduledTask_AutoUpdate_DriverBlockRules) {
        Invoke-Command -ScriptBlock $Make_ScheduledTask_AutoUpdate_DriverBlockRulesSCRIPTBLOCK
    }                                
    if ($Make_PolicyFromAuditLogs) {
        Invoke-Command -ScriptBlock $Make_PolicyFromAuditLogsSCRIPTBLOCK
    }                                
    if ($Prep_SystemFor_MSFTOnlyAudit) {
        Invoke-Command -ScriptBlock $Prep_SystemFor_MSFTOnlyAuditSCRIPTBLOCK
    }
    if ($Make_LightlyManagedPolicy) {
        Invoke-Command -ScriptBlock $Make_LightlyManagedPolicySCRIPTBLOCK
    }
    if ($Sign_Deploy_Policy) {
        Invoke-Command -ScriptBlock $Sign_Deploy_PolicySCRIPTBLOCK
    }
    if ($Make_SupplementalPolicy) {
        Invoke-Command -ScriptBlock $Make_SupplementalPolicySCRIPTBLOCK
    }
    if ($RemoveSignedPolicy) {
        Invoke-Command -ScriptBlock $RemoveSignedPolicySCRIPTBLOCK
    }
    if ($AfterRebootRemoval) {
        Invoke-Command -ScriptBlock $AfterRebootRemovalSCRIPTBLOCK
    }
    if ($ListActivePolicies) {
        Invoke-Command -ScriptBlock $ListActivePoliciesSCRIPTBLOCK
    }
    if ($VerifyWDACStatus) {
        Invoke-Command -ScriptBlock $VerifyWDACStatusSCRIPTBLOCK
    }
    if ($RemoveUNsignedPolicy) {
        Invoke-Command -ScriptBlock $RemoveUNsignedPolicySCRIPTBLOCK
    }
    #endregion function-processing

    <#
.SYNOPSIS
Automate a lot of tasks related to WDAC (Windows Defender Application Control)

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-ConfigWDAC

.DESCRIPTION
Using official Microsoft methods, configure and use Windows Defender Application Control

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Automate various tasks related to Windows Defender Application Control (WDAC)

.PARAMETER Get_RecommendedBlockRules
Create Microsoft recommended block rules XML policy and remove the allow rules

.PARAMETER Get_RecommendedDriverBlockRules
Create Microsoft recommended driver block rules XML policy and remove the allow rules

.PARAMETER Make_AllowMSFT_WithReccBlockRules
Make WDAC policy by merging AllowMicrosoft policy with the recommended block rules

.PARAMETER Deploy_LatestDriverBlockRules
Automatically download and deploy the latest Microsoft Recommended Driver Block Rules from Microsoft's source

.PARAMETER Make_ScheduledTask_AutoUpdate_DriverBlockRules
Make a Scheduled Task that automatically runs every 7 days to download the newest Microsoft Recommended driver block rules

.PARAMETER Make_PolicyFromAuditLogs
Make WDAC Policy from Audit event logs that also covers files no longer on disk

.PARAMETER Prep_SystemFor_MSFTOnlyAudit
Prepare the system for Audit mode using AllowMicrosoft example policy

.PARAMETER Make_LightlyManagedPolicy
Make WDAC Policy with ISG for Lightly Managed system

.PARAMETER ListActivePolicies
List the non-System WDAC Policies

.PARAMETER VerifyWDACStatus
Shows the status of User-mode and Kernel-mode Windows Defender Application Control deployments

.PARAMETER Sign_Deploy_Policy 
Sign and deploy a WDAC policy

.PARAMETER Make_SupplementalPolicy 
Make a Supplemental policy by scanning a directory    

.PARAMETER RemoveSignedPolicy
Remove Signed WDAC Policies, can remove more than 1 at a time.

.PARAMETER AfterRebootRemoval
Complete removal of a Signed WDAC policy

.PARAMETER RemoveUNsignedPolicy
Removes Unsigned deployed WDAC policies, requires PolicyIDs as input, can remove more than 1 at a time.

#>
}

# argument tab auto-completion for Policy IDs
$ArgumentCompleterPolicyID = {
    ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.IsSystemPolicy -ne "True" }).policyID
}
Register-ArgumentCompleter -CommandName "New-ConfigWDAC" -ParameterName "PolicyIDs" -ScriptBlock $ArgumentCompleterPolicyID

# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadlineKeyHandler -Key Tab -Function MenuComplete
