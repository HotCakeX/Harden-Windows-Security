#requires -version 7.3.3
Function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity
    $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if (-NOT (Test-IsAdmin)) {
    write-host "Administrator privileges Required" -ForegroundColor Magenta
    break
}
function New-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = "set1",
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = "set1", Position = 0, ValueFromPipeline = $true)][switch]$Get_BlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set2", Position = 0, ValueFromPipeline = $true)][switch]$Get_DriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set3", Position = 0, ValueFromPipeline = $true)][switch]$Make_AllowMSFT_WithBlockRules,  
        [Parameter(Mandatory = $false, ParameterSetName = "set4", Position = 0, ValueFromPipeline = $true)][switch]$Deploy_LatestDriverBlockRules,                                                                                       
        [Parameter(Mandatory = $false, ParameterSetName = "set5", Position = 0, ValueFromPipeline = $true)][switch]$Set_AutoUpdateDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set6", Position = 0, ValueFromPipeline = $true)][switch]$Prep_MSFTOnlyAudit,
        [Parameter(Mandatory = $false, ParameterSetName = "set7", Position = 0, ValueFromPipeline = $true)][switch]$Make_PolicyFromAuditLogs,  
        [Parameter(Mandatory = $false, ParameterSetName = "set8", Position = 0, ValueFromPipeline = $true)][switch]$Make_LightPolicy,
        [Parameter(Mandatory = $false, ParameterSetName = "set9", Position = 0, ValueFromPipeline = $true)][switch]$Make_SuppPolicy,
       
        [parameter(Mandatory = $true, ParameterSetName = "set9", ValueFromPipelineByPropertyName = $true)][string]$ScanLocation,
        [parameter(Mandatory = $true, ParameterSetName = "set9", ValueFromPipelineByPropertyName = $true)][string]$SuppPolicyName,
        [parameter(Mandatory = $true, ParameterSetName = "set9", ValueFromPipelineByPropertyName = $true)][string]$PolicyPath,

        [Parameter(Mandatory = $false, ParameterSetName = "set3")]
        [Parameter(Mandatory = $false, ParameterSetName = "set7")]
        [Parameter(Mandatory = $false, ParameterSetName = "set8")]        
        [parameter(Mandatory = $false, ParameterSetName = "set9")]
        [switch]$Deployit,

        [Parameter(Mandatory = $false, ParameterSetName = "set8")]
        [Parameter(Mandatory = $false, ParameterSetName = "set7")]
        [Parameter(Mandatory = $false, ParameterSetName = "set3")]
        [switch]$TestMode,
        
        [Parameter(Mandatory = $false, ParameterSetName = "set3")]
        [Parameter(Mandatory = $false, ParameterSetName = "set7")]
        [Parameter(Mandatory = $false, ParameterSetName = "set8")]
        [switch]$RequireEVSigners,

        [Parameter(Mandatory = $false, ParameterSetName = "set7")][switch]$Debugmode,

        [ValidateRange(1024KB, [int64]::MaxValue)]
        [Parameter(Mandatory = $false, ParameterSetName = "set6")]
        [Parameter(Mandatory = $false, ParameterSetName = "set7")]        
        [Int64]$LogSize,

        [Parameter(Mandatory = $false)][switch]$SkipVersionCheck
    )

    $ErrorActionPreference = 'Stop'


    # Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
    if (-NOT $SkipVersionCheck) {
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


    #region Misc-Functions    
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
    #endregion Misc-Functions    

    #region Main-Script-Blocks    
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
    $Get_DriverBlockRulesSCRIPTBLOCK = {       
        $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md"
       
        $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)" | Out-Null
        $DriverRules = $Matches[0]

        $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_1"\sFriendlyName=""\sFileName="\*".*/>', ''
        $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_2"\sFriendlyName=""\sFileName="\*".*/>', ''
        $DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_1".*/>', ''

        # not using this one because then during the merge there will be error - The reason is that "<FileRuleRef RuleID="ID_ALLOW_ALL_2" />" is the only FileruleRef in the xml and after removing it, the <SigningScenario> element will be empty
        #$DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_2".*/>',''
        $DriverRules = $DriverRules -replace '<SigningScenario\sValue="12"\sID="ID_SIGNINGSCENARIO_WINDOWS"\sFriendlyName="Auto\sgenerated\spolicy[\S\s]*<\/SigningScenario>', ''

        $DriverRules | Out-File '.\Microsoft recommended driver block rules TEMP.xml'

        Get-Content '.\Microsoft recommended driver block rules TEMP.xml' | Where-Object { $_.trim() -ne "" } | Out-File '.\Microsoft recommended driver block rules.xml'
        Remove-Item '.\Microsoft recommended driver block rules TEMP.xml' -Force
        Set-RuleOption -FilePath '.\Microsoft recommended driver block rules.xml' -Option 3 -Delete
        Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended driver block rules.xml'
        
        Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK

        [PSCustomObject]@{
            PolicyFile = "Microsoft recommended driver block rules.xml"
        }        
    }
    $Make_AllowMSFT_WithBlockRulesSCRIPTBLOCK = {
        param([bool]$NoCIP)
        Invoke-Command -ScriptBlock $Get_BlockRulesSCRIPTBLOCK | Out-Null                        
        Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
        Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.xml' -OutputFilePath .\AllowMicrosoftPlusBlockRules.xml | Out-Null     
        $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoftPlusBlockRules.xml -PolicyName "DefaultAllowMicrosoft Plus ReccommendedBlockRules Made On $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
        $PolicyID = $PolicyID.Substring(11)
        Set-CIPolicyVersion -FilePath .\AllowMicrosoftPlusBlockRules.xml -Version "1.0.0.0"
        @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ }
        @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ -Delete }        
        if ($TestMode -and $Make_AllowMSFT_WithBlockRules) {
            & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting .\AllowMicrosoftPlusBlockRules.xml
        }
        if ($RequireEVSigners -and $Make_AllowMSFT_WithBlockRules) {
            & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners .\AllowMicrosoftPlusBlockRules.xml
        }        
        Set-HVCIOptions -Strict -FilePath .\AllowMicrosoftPlusBlockRules.xml
        ConvertFrom-CIPolicy .\AllowMicrosoftPlusBlockRules.xml "$PolicyID.cip" | Out-Null   

        Remove-Item .\AllowMicrosoft.xml -Force
        Remove-Item '.\Microsoft recommended block rules.xml' -Force

        [PSCustomObject]@{
            PolicyFile = "AllowMicrosoftPlusBlockRules.xml"
            BinaryFile = "$PolicyID.cip"
        }

        if ($Deployit -and $Make_AllowMSFT_WithBlockRules) {            
            CiTool --update-policy ".\$PolicyID.cip" -json
            Write-host "`nAllowMicrosoftPlusBlockRules.xml policy has been deployed and its GUID is $PolicyID" -ForegroundColor Cyan
        }
        if ($NoCIP)
        { Remove-Item -Path "$PolicyID.cip" -Force }
    }   
    $Deploy_LatestDriverBlockRulesSCRIPTBLOCK = {        
        Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip      
        Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force
        Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force
        Copy-item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity"
        citool --refresh -json
        Remove-Item .\VulnerableDriverBlockList -Recurse -Force
        Remove-Item .\VulnerableDriverBlockList.zip -Force
        Write-Host "`nSiPolicy.p7b has been deployed and policies refreshed." -ForegroundColor Cyan        
        Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
    }    
    $Set_AutoUpdateDriverBlockRulesSCRIPTBLOCK = {
        # create a scheduled task that runs every 7 days
        if (-NOT (Get-ScheduledTask -TaskName "MSFT Driver Block list update" -ErrorAction SilentlyContinue)) {        
            $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit};Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'    
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
        Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
    }
    $Prep_MSFTOnlyAuditSCRIPTBLOCK = {
        if ($Prep_MSFTOnlyAudit -and $LogSize) { Set-LogSize -LogSize $LogSize }
        Copy-item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\AllowMicrosoft.xml
        Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option 3
        $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
        $PolicyID = $PolicyID.Substring(11)
        Set-CIPolicyIdInfo -PolicyName "Prep_MSFTOnlyAudit" -FilePath .\AllowMicrosoft.xml
        ConvertFrom-CIPolicy .\AllowMicrosoft.xml "$PolicyID.cip" | Out-Null
        CiTool --update-policy "$PolicyID.cip" -json
        Remove-Item ".\AllowMicrosoft.xml" -Force
        Remove-Item "$PolicyID.cip" -Force
        Write-host "`nThe default AllowMicrosoft policy has been deployed in Audit mode. No reboot required." -ForegroundColor Magenta     
    }
    $Make_PolicyFromAuditLogsSCRIPTBLOCK = {
        if ($Make_PolicyFromAuditLogs -and $LogSize) { Set-LogSize -LogSize $LogSize }
        Remove-Item -Path "$home\WDAC\*" -Recurse -Force -ErrorAction SilentlyContinue
        # Create a working directory in user's folder
        new-item -Type Directory -Path "$home\WDAC" -Force | Out-Null
        Set-Location "$home\WDAC"

        # Base Policy Processing        
        Invoke-Command -ScriptBlock $Make_AllowMSFT_WithBlockRulesSCRIPTBLOCK | Out-Null
        $xml = [xml](Get-Content .\AllowMicrosoftPlusBlockRules.xml)
        $BasePolicyID = $xml.SiPolicy.PolicyID
        # define the location of the base policy
        $BasePolicy = ".\AllowMicrosoftPlusBlockRules.xml"        
      
        if ($TestMode -and $Make_PolicyFromAuditLogs) {
            & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting $BasePolicy
        }
        if ($RequireEVSigners -and $Make_PolicyFromAuditLogs) {
            & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners $BasePolicy
        }

        # Supplemental Processing

        # produce policy xml file from event viewer logs
        Write-host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan
        New-CIPolicy -FilePath ".\AuditLogsPolicy_NoDeletedFiles.xml" -Audit -Level SignedVersion -Fallback FilePublisher, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths -WarningAction SilentlyContinue                               
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

            $EmptyPolicy | Out-File .\DeletedFilesHashes.xml

            # Merge the policy file we created at first using Event Viewer logs, with the policy file we created for Hash of the files no longer available on the disk
            Merge-CIPolicy -PolicyPaths ".\AuditLogsPolicy_NoDeletedFiles.xml", .\DeletedFilesHashes.xml -OutputFilePath .\SupplementalPolicy.xml
        }
        # do this only if there are no event logs detected with files no longer on the disk, so we use the policy file created earlier using Audit even logs
        else {
            Rename-Item ".\AuditLogsPolicy_NoDeletedFiles.xml" -NewName "SupplementalPolicy.xml" -Force
        }      
        # Convert the SupplementalPolicy.xml policy file from base policy to supplemental policy of our base policy
        Set-CIPolicyVersion -FilePath ".\SupplementalPolicy.xml" -Version "1.0.0.0"
        $PolicyID = Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy.xml" -PolicyName "Supplemental Policy made from Audit Event Logs on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $BasePolicy
        $PolicyID = $PolicyID.Substring(11)        
        # Make sure policy rule options that don't belong to a Supplemental policy don't exit
        @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath ".\SupplementalPolicy.xml" -Option $_ -Delete }

        # Set the hypervisor Code Integrity option for Supplemental policy to Strict        
        Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy.xml"
        # convert the Supplemental Policy file to .cip binary file
        ConvertFrom-CIPolicy ".\SupplementalPolicy.xml" "$policyID.cip" | Out-Null

        [PSCustomObject]@{
            BasePolicyFile = "AllowMicrosoftPlusBlockRules.xml"      
            BasePolicyGUID = $BasePolicyID
        }
        [PSCustomObject]@{
            SupplementalPolicyFile = "SupplementalPolicy.xml"
            SupplementalPolicyGUID = $PolicyID
        }       

        if (-NOT $Debugmode) {
            Remove-Item -Path ".\AuditLogsPolicy_NoDeletedFiles.xml" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path ".\FileRulesAndFileRefs.txt" -Force -ErrorAction SilentlyContinue
            Remove-Item -Path ".\DeletedFilesHashes.xml" -Force -ErrorAction SilentlyContinue
        }
        if ($Deployit -and $Make_PolicyFromAuditLogs) {            
            CiTool --update-policy ".\$BasePolicyID.cip" -json
            CiTool --update-policy ".\$policyID.cip" -json
            Write-host "`nBase policy and Supplemental Policies deployed and activated." -ForegroundColor Green                       
        }        
        do {
            $RemovalQuestion = $(Write-host "`nRemove the Audit mode MicrosoftOnly policy deployed during the prep phase? Enter 1 for Yes, 2 for No." -ForegroundColor Cyan; Read-Host)     
            if ($RemovalQuestion -eq "1" ) {
                $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq "Prep_MSFTOnlyAudit" }).PolicyID
                CiTool --remove-policy "{$IDToRemove}"
                Write-host "System restart required to finish removing the Audit mode Prep policy" -ForegroundColor Green                   
            }
            if ($RemovalQuestion -eq "2" ) {
                Write-host "Skipping" -ForegroundColor Yellow
            }         
        }                  
        until ($RemovalQuestion -eq "1" -or $RemovalQuestion -eq "2")            
    }
    $Make_LightPolicySCRIPTBLOCK = {
        Remove-Item -Path ".\SignedAndReputable.xml" -Force -ErrorAction SilentlyContinue
        Invoke-Command -ScriptBlock $Make_AllowMSFT_WithBlockRulesSCRIPTBLOCK -ArgumentList $true | Out-Null 
        Rename-Item -Path ".\AllowMicrosoftPlusBlockRules.xml" -NewName "SignedAndReputable.xml" -Force
        @(14, 15) | ForEach-Object { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }
        if ($TestMode -and $Make_LightPolicy) {
            & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting .\SignedAndReputable.xml
        }
        if ($RequireEVSigners -and $Make_LightPolicy) {
            & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners .\SignedAndReputable.xml
        }
        $BasePolicyID = Set-CiPolicyIdInfo -FilePath .\SignedAndReputable.xml -ResetPolicyID -PolicyName "SignedAndReputable policy deployed on $(Get-Date -Format 'MM-dd-yyyy')"
        $BasePolicyID = $BasePolicyID.Substring(11)        
        Set-CIPolicyVersion -FilePath .\SignedAndReputable.xml -Version "1.0.0.0"
        Set-HVCIOptions -Strict -FilePath .\SignedAndReputable.xml        
        ConvertFrom-CIPolicy .\SignedAndReputable.xml "$BasePolicyID.cip" | Out-Null 
        appidtel start
        sc.exe config appidsvc start= auto
        if ($Deployit -and $Make_LightPolicy) {
            CiTool --update-policy ".\$BasePolicyID.cip" -json
            Write-host -NoNewline "`nSignedAndReputable.xml policy has been deployed.`n" -ForegroundColor Green            
        }
        [PSCustomObject]@{
            BasePolicyFile = "SignedAndReputable.xml"      
            BasePolicyGUID = $BasePolicyID
        }       
    }
    $Make_SuppPolicySCRIPTBLOCK = {
        New-CIPolicy -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -ScanPath $ScanLocation `
            -Level SignedVersion -Fallback FilePublisher, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths
        $policyID = Set-CiPolicyIdInfo -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName"
        $policyID = $policyID.Substring(11)
        Set-CIPolicyVersion -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -Version "1.0.0.0"
        # Make sure policy rule options that don't belong to a Supplemental policy don't exit             
        @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object {
            Set-RuleOption -FilePath ".\SupplementalPolicy$SuppPolicyName.xml" -Option $_ -Delete }        
        Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy$SuppPolicyName.xml"        
        ConvertFrom-CIPolicy ".\SupplementalPolicy$SuppPolicyName.xml" "$policyID.cip" | Out-Null
        [PSCustomObject]@{
            SupplementalPolicyFile = "SupplementalPolicy$SuppPolicyName.xml"
            SupplementalPolicyGUID = $PolicyID
        } 
        if ($Deployit) {                
            CiTool --update-policy "$policyID.cip" -json
            Write-host -NoNewline "`n$policyID.cip for " -ForegroundColor Green;
            Write-host -NoNewline "$SuppPolicyName" -ForegroundColor Magenta;
            Write-host " has been deployed." -ForegroundColor Green
        }
        
    }
    #endregion Main-Script-Blocks


    #region Misc-Script-Blocks
    $TestModeSCRIPTBLOCK = { 
        param($PolicyPathToEnableTesting)
        @(9, 10) | ForEach-Object { Set-RuleOption -FilePath $PolicyPathToEnableTesting -Option $_ }
    }
    $RequireEVSignersSCRIPTBLOCK = {
        param($PolicyPathToEnableEVSigners)
        Set-RuleOption -FilePath $PolicyPathToEnableEVSigners -Option 8
    }
    $DriversBlockListInfoGatheringSCRIPTBLOCK = {
        $owner = "MicrosoftDocs"
        $repo = "windows-itpro-docs"
        $path = "windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md"

        $apiUrl = "https://api.github.com/repos/$owner/$repo/commits?path=$path"
        $response = Invoke-RestMethod -Uri $apiUrl -Method Get
        $date = $response[0].commit.author.date

        Write-Host "`nThe document containing the drivers block list on GitHub was last updated on $date" -ForegroundColor Magenta

        $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md"
        $MicrosoftRecommendeDriverBlockRules -match "<VersionEx>(.*)</VersionEx>" | Out-Null
        
        Write-Host "`nThe current version of Microsoft recommended drivers block list is $($Matches[1])" -ForegroundColor Cyan
    }    
    #endregion Misc-Script-Blocks    

    
    #region Main-Function-Processing
    if ($Get_BlockRules) {              
        Invoke-Command -ScriptBlock $Get_BlockRulesSCRIPTBLOCK
    }                                
    if ($Get_DriverBlockRules) {
        Invoke-Command -ScriptBlock $Get_DriverBlockRulesSCRIPTBLOCK
    }   
    if ($Make_AllowMSFT_WithBlockRules) {
        Invoke-Command -ScriptBlock $Make_AllowMSFT_WithBlockRulesSCRIPTBLOCK
    }
    if ($Deploy_LatestDriverBlockRules) {
        Invoke-Command -ScriptBlock $Deploy_LatestDriverBlockRulesSCRIPTBLOCK
    }                               
    if ($Set_AutoUpdateDriverBlockRules) {
        Invoke-Command -ScriptBlock $Set_AutoUpdateDriverBlockRulesSCRIPTBLOCK
    }                                
    if ($Make_PolicyFromAuditLogs) {
        Invoke-Command -ScriptBlock $Make_PolicyFromAuditLogsSCRIPTBLOCK
    }                                
    if ($Prep_MSFTOnlyAudit) {
        Invoke-Command -ScriptBlock $Prep_MSFTOnlyAuditSCRIPTBLOCK
    }
    if ($Make_LightPolicy) {
        Invoke-Command -ScriptBlock $Make_LightPolicySCRIPTBLOCK
    }
    if ($Make_SuppPolicy) {
        Invoke-Command -ScriptBlock $Make_SuppPolicySCRIPTBLOCK
    }
    #endregion Main-Function-Processing

    <#
.SYNOPSIS
Automate a lot of tasks related to WDAC (Windows Defender Application Control)

.LINK
https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDACConfig

.DESCRIPTION
Using official Microsoft methods, configure and use Windows Defender Application Control

.COMPONENT
Windows Defender Application Control

.FUNCTIONALITY
Automate various tasks related to Windows Defender Application Control (WDAC)

.PARAMETER Get_BlockRules
Create Microsoft recommended block rules xml policy and remove the allow rules

.PARAMETER Get_DriverBlockRules
Create Microsoft recommended driver block rules xml policy and remove the allow rules

.PARAMETER Make_AllowMSFT_WithBlockRules
Make WDAC policy by merging AllowMicrosoft policy with the recommended block rules

.PARAMETER Deploy_LatestDriverBlockRules
Automatically download and deploy the latest Microsoft Recommended Driver Block Rules from Microsoft's source

.PARAMETER Set_AutoUpdateDriverBlockRules
Make a Scheduled Task that automatically runs every 7 days to download the newest Microsoft Recommended driver block rules

.PARAMETER Prep_MSFTOnlyAudit
Prepare the system for Audit mode using AllowMicrosoft default policy

.PARAMETER Make_PolicyFromAuditLogs
Make WDAC Policy from Audit event logs that also covers files no longer on disk

.PARAMETER Make_LightPolicy
Make WDAC Policy with ISG for Lightly Managed system

.PARAMETER Make_SuppPolicy 
Make a Supplemental policy by scanning a directory    

.PARAMETER SkipVersionCheck
Can be used with any parameter to bypass the online version check - only to be used in rare cases

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
Register-ArgumentCompleter -CommandName "New-WDACConfig" -ParameterName "PolicyPath" -ScriptBlock $ArgumentCompleterPolicyPaths
