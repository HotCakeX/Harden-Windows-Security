function New-ConfigWDAC {
    [CmdletBinding(
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction"
    )
    ]  Param(
        [Parameter(Mandatory = $false)][switch]$GetRecommendedBlockRules,
        [Parameter(Mandatory = $false)][switch]$GetRecommendedDriverBlockRules,
        [Parameter(Mandatory = $false)][switch]$MergeBothBlockRulesWithAllowMicrosoft,
        [Parameter(Mandatory = $false)][switch]$InstallLatestDriverBlockRules,
        [Parameter(Mandatory = $false)][switch]$CreateTaskScheduleAutoDriverBlockRules,
        [Parameter(Mandatory = $false)][switch]$CreatePolicyAuditEventLogs
    )
    
    #region Script-Blocks

    # Create Microsoft recommended block rules XML policy and remove the allow rules
    $GetRecommendedBlockRulesSCRIPTBLOCK = {        
        $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md"
        $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)"

        $Rules = $Matches[0]

        $Rules | Out-File '.\Microsoft recommended block rules.XML'

        $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_1"\sFriendlyName="Allow\sKernel\sDrivers"\sFileName="\*".*/>', ''
        $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_2"\sFriendlyName="Allow\sUser\smode\scomponents"\sFileName="\*".*/>', ''
        $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_1".*/>', ''
        $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_2".*/>', ''

        $Rules | Out-File '.\Microsoft recommended block rules TEMP.XML'

        Get-Content '.\Microsoft recommended block rules TEMP.XML' | Where-Object { $_.trim() -ne "" } | Out-File '.\Microsoft recommended block rules.XML'

        Remove-Item '.\Microsoft recommended block rules TEMP.XML' -Force
    }   

    # Create Microsoft recommended driver block rules XML policy and remove the allow rules
    $GetRecommendedDriverBlockRulesSCRIPTBLOCK = {        
        $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md"
        $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)"

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
    }

    # Automatically download and install Microsoft Recommended Driver Block Rules
    $InstallLatestDriverBlockRulesSCRIPTBLOCK = {
        Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip
        Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force
        Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force
        Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity"
        $job = Start-Job -Name "Job1" -ScriptBlock { CiTool.exe -r }
        Start-Sleep -s 15
        Stop-Job $job
        Remove-Item .\VulnerableDriverBlockList -Recurse -Force
        Remove-Item .\VulnerableDriverBlockList.zip -Force
    }

    # Create a Scheduled Task that automatically runs every 7 days to download the newest Microsoft Recommended driver block rules
    $CreateTaskScheduleAutoDriverBlockRulesSCRIPTBLOCK = {
        # create a scheduled task that runs every 7 days
        if (-NOT (Get-ScheduledTask -TaskName "MSFT Driver Block list update" -ErrorAction SilentlyContinue)) {        
            $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                -Argument '-NoProfile -WindowStyle Hidden -command "& {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip;Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";$job = Start-Job -Name "Job1" -ScriptBlock { CiTool.exe -r };Start-Sleep -s 15;Stop-Job $job;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'    
            $TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $env:USERNAME -RunLevel Highest
            # trigger
            $Time = 
            New-ScheduledTaskTrigger `
                -Once -At (Get-Date).AddHours(3) `
                -RepetitionInterval (New-TimeSpan -Days 7) `
                # register the task
                Register-ScheduledTask -Action $action -Trigger $Time -Principal $TaskPrincipal -TaskPath "MSFT Driver Block list update" -TaskName "MSFT Driver Block list update" -Description "Microsoft Recommended Driver Block List update"
            # define advanced settings for the task
            $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
            # add advanced settings we defined to the task
            Set-ScheduledTask -TaskPath "MSFT Driver Block list update" -TaskName "MSFT Driver Block list update" -Settings $TaskSettings 
        }
    }

    #
    $CreatePolicyAuditEventLogsSCRIPTBLOCK = {
        # Make sure there is no lingering variable from previous runs - prevent the outfile from getting duplicate rules/ruleRefs if user run this script multiple times
        Remove-Variable * -ErrorAction SilentlyContinue
        # Create a working directory in user's folder
        new-item -Type Directory -Path "$home\WDAC" -Force | Out-Null
        Set-Location "$home\WDAC"
        # Take the AllowMicrosoft.xml policy file from Windows folder and use it as the base policy - reset its policy ID and make sure it doesn't have Audit mode rule option
        Copy-Item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\
        Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID | Out-Null
        # define the location of the base policy
        $BasePolicy = "$home\WDAC\AllowMicrosoft.xml"
        # produce policy XML file from event viewer logs
        Write-Host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan
        New-CIPolicy -FilePath .\Policy_LeafCertificate_FallBack_SignedVersion_FileName_FilePublisher_Hash.xml -Audit -Level LeafCertificate -Fallback SignedVersion, FileName, FilePublisher, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths 3> Warnings.txt

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

        # Create an empty Policy XML template file
        Write-Host "Creating a template policy file, please wait..." -ForegroundColor Cyan
        New-CIPolicy -FilePath .\policy.xml -Audit -Level None -MultiplePolicyFormat 3> $null
        # Store our $Rules in the FileRules section of this empty policy template
        $xmlAsText = (Get-Content '.\policy.xml' -Raw)
        $pattern1 = "<FileRules />"
        $realcontent = "<FileRules>$Rules</FileRules>"
        # create a new file called DeletedFilesHashes.XML that now contains template policy PLUS our File Rules from $Rules variable
        $xmlAsText -Replace ($pattern1, $realcontent) | Set-Content ".\DeletedFilesHashes.XML"

        # Read the new DeletedFilesHashes.XML policy file
        $xmlAsText = (Get-Content ".\DeletedFilesHashes.XML" -Raw)

        # Delete the empty policy file we generated to use as template
        remove-item .\policy.xml

        # Store our $RulesRefs in the FileRulesRefs section of the Signing Scenarios
        # Using regex here because haven't had luck figuring out how to create a compatible Signing Scenario Value number and ID
        $pattern2 = '<SigningScenario[\s]Value="12"[\s]ID="ID_SIGNINGSCENARIO_WINDOWS"[\s][\s\S].*[\s\S].*[\s\S].*'
        $xmlAsText -match $pattern2
        $currentRules = $matches[0]
        $RulesReftoReplace = @"
<SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 02-21-2023">
<ProductSigners>
<FileRulesRef>
$RulesRefs
</FileRulesRef>
</ProductSigners>
</SigningScenario>
"@
        $NewRules = $RulesReftoReplace + $currentRules
        $xmlAsText -Replace ($pattern2, $NewRules) | Set-Content ".\DeletedFilesHashes.XML"

        # Merge the policy file we created at first using Event Viewer logs, with the policy file we created for Hash of the files no longer available on the disk
        Merge-CIPolicy -PolicyPaths .\Policy_LeafCertificate_FallBack_SignedVersion_FileName_FilePublisher_Hash.xml, .\DeletedFilesHashes.XML -OutputFilePath .\SupplementalPolicy.xml

        $xml = [xml](Get-Content ".\SupplementalPolicy.xml")
        $PolicyID = $xml.SiPolicy.PolicyID
        write-host  "This is the GUID of the Supplemental Policy: $PolicyID" -ForegroundColor Magenta
        # Convert the SupplementalPolicy.XML policy file from base policy to supplemental policy of our base policy
        Set-CIPolicyIdInfo -FilePath ".\SupplementalPolicy.xml" -BasePolicyToSupplementPath $BasePolicy

        # Set the base policy rule options 
        @(0, 2, 6, 11, 12, 16, 17, 18, 19, 20) | ForEach-Object { Set-RuleOption -FilePath $BasePolicy -Option $_ }
        @(1, 3, 4, 5, 7, 8, 9, 10, 13, 14, 15) | ForEach-Object { Set-RuleOption -FilePath $BasePolicy -Option $_ -Delete }

        # Set the Supplemental policy rule options
        @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath ".\SupplementalPolicy.xml" -Option $_ -Delete }

        # Set the hypervisor Code Integrity option for Base and Supplemental policies to Strict
        Set-HVCIOptions -Strict -FilePath $BasePolicy 
        Set-HVCIOptions -Strict -FilePath ".\SupplementalPolicy.xml"

        # convert the Supplemental Policy file into .cip binary file
        ConvertFrom-CIPolicy ".\SupplementalPolicy.xml" "$policyID.cip"
        # convert the Base policy file into .cip binary file
        $xml = [xml](Get-Content ".\AllowMicrosoft.xml")
        $PolicyID = $xml.SiPolicy.PolicyID
        write-host  "This is the GUID of the Base Policy: $PolicyID" -ForegroundColor Magenta
        ConvertFrom-CIPolicy .\AllowMicrosoft.xml "$policyID.cip"

    }
    #endregion Script-Blocks

    #region function-processing
    if ($GetRecommendedBlockRules) {              
        Invoke-Command -ScriptBlock $GetRecommendedBlockRulesSCRIPTBLOCK
    }
    if ($GetRecommendedDriverBlockRules) {
        Invoke-Command -ScriptBlock $GetRecommendedDriverBlockRulesSCRIPTBLOCK
    }
    if ($MergeBothBlockRulesWithAllowMicrosoft) {
        Invoke-Command -ScriptBlock $GetRecommendedBlockRulesSCRIPTBLOCK
        Invoke-Command -ScriptBlock $GetRecommendedDriverBlockRulesSCRIPTBLOCK

        Copy-Item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"

        Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.XML', '.\Microsoft recommended driver block rules.XML' -OutputFilePath .\AllowMicrosoftPlusBlockRules.XML

    }
    if ($InstallLatestDriverBlockRules) {
        Invoke-Command -ScriptBlock $InstallLatestDriverBlockRulesSCRIPTBLOCK
    }
    if ($CreateTaskScheduleAutoDriverBlockRules) {
        Invoke-Command -ScriptBlock $CreateTaskScheduleAutoDriverBlockRulesSCRIPTBLOCK
    }
    if ($CreatePolicyAuditEventLogs){
        Invoke-Command -ScriptBlock $CreatePolicyAuditEventLogsSCRIPTBLOCK
    }
    #endregion function-processing
}

