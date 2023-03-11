#requires -version 7.3.3
function New-ConfigWDAC {
    [CmdletBinding(
        DefaultParameterSetName = "set1",
        HelpURI = "https://github.com/HotCakeX/Harden-Windows-Security/wiki/WDAC-Module"
    )]
    Param(
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Get_Recommended_Block_Rules,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Get_Recommended_Driver_Block_Rules,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Create_AllowMicrosoft_With_Rec_BlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Deploy_AllowMicrosoft_With_Rec_BlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Deploy_Latest_Driver_BlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Create_Scheduled_Task_Auto_Driver_BlockRules_Update,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Create_WDAC_Policy_From_Audit_Logs,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Prep_System_For_MSFT_Only_Audit,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Create_Lightly_Managed_WDAC_Policy,
        [Parameter(Mandatory = $false, ParameterSetName = "set1")][switch]$Deploy_Lightly_Managed_WDAC_Policy,
        [Parameter(Mandatory = $false, ParameterSetName = "set2")][switch]$Sign_Deploy_Policy,       
        [parameter(ParameterSetName = "set2", Mandatory = $true)][string]$WDACPolicyPath,
        [parameter(ParameterSetName = "set2", Mandatory = $true)][string]$CertPath,
        [parameter(ParameterSetName = "set2", Mandatory = $true)][string]$CertCN,
        [parameter(ParameterSetName = "set2", Mandatory = $false)][string]$SignToolExePath
        
    )

    #region Script-Blocks

    # Create Microsoft recommended block rules XML policy and remove the allow rules
    $Get_Recommended_Block_RulesSCRIPTBLOCK = {
        try {
            $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md" -ErrorAction Stop
        }
        catch {
            Write-Error "Couldn't download the required resource, check your Internet connection"
            break
        }

        $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)"

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
    }   

    # Create Microsoft recommended driver block rules XML policy and remove the allow rules
    $Get_Recommended_Driver_Block_RulesSCRIPTBLOCK = {
        try {
            $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md" -ErrorAction Stop
        }
        catch {
            Write-Error "Couldn't download the required resource, check your Internet connection"
            break
        }

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

        Set-RuleOption -FilePath '.\Microsoft recommended driver block rules.XML' -Option 3 -Delete

        Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended driver block rules.XML'
    }

    # Create WDAC policy by merging AllowMicrosoft policy with the recommended block rules
    $Create_AllowMicrosoft_With_Rec_BlockRulesSCRIPTBLOCK = {
        Invoke-Command -ScriptBlock $Get_Recommended_Block_RulesSCRIPTBLOCK
                              
        Copy-Item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"

        Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.XML' -OutputFilePath .\AllowMicrosoftPlusBlockRules.XML
        
        $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoftPlusBlockRules.XML -ResetPolicyID

        $PolicyID = $PolicyID.Substring(11)

        Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.XML -Option 3 -Delete

        @(2, 11, 12, 20) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.XML -Option $_ }

        Set-HVCIOptions -Strict -FilePath .\AllowMicrosoftPlusBlockRules.XML

        ConvertFrom-CIPolicy .\AllowMicrosoftPlusBlockRules.XML "$PolicyID.cip"

        Remove-Item .\AllowMicrosoft.xml -Force
        Remove-Item '.\Microsoft recommended block rules.XML' -Force
    }

    # Deploy WDAC policy created by merging AllowMicrosoft policy with the recommended block rules
    $Deploy_AllowMicrosoft_With_Rec_BlockRulesSCRIPTBLOCK = {
        Invoke-Command -ScriptBlock $Create_AllowMicrosoft_With_Rec_BlockRulesSCRIPTBLOCK
        $xml = [xml](Get-Content ".\AllowMicrosoftPlusBlockRules.XML")
        $PolicyID = $xml.SiPolicy.PolicyID
        Move-Item -Path "$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
        Write-Host "The AllowMicrosoftPlusBlockRules policy has been deployed and its GUID is $PolicyID" -ForegroundColor Cyan
    }

    # Automatically download and install Microsoft Recommended Driver Block Rules
    $Deploy_Latest_Driver_BlockRulesSCRIPTBLOCK = {
        try {
            Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop
        }
        catch {
            Write-Error "Couldn't download the required resource, check your Internet connection"
            break
        }
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
    $Create_Scheduled_Task_Auto_Driver_BlockRules_UpdateSCRIPTBLOCK = {
        # create a scheduled task that runs every 7 days
        if (-NOT (Get-ScheduledTask -TaskName "MSFT Driver Block list update" -ErrorAction SilentlyContinue)) {        
            $action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit};Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";$job = Start-Job -Name "Job1" -ScriptBlock { CiTool.exe -r };Start-Sleep -s 15;Stop-Job $job;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'    
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

    # Create WDAC Policy from Audit event logs that also covers files no longer on disk
    $Create_WDAC_Policy_From_Audit_LogsSCRIPTBLOCK = {
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
        Write-Host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan
        New-CIPolicy -FilePath .\WDAC_From_AuditEvents.xml -Audit -Level PcaCertificate -Fallback FilePublisher, Publisher, SignedVersion, FileName, Hash -UserPEs -MultiplePolicyFormat -UserWriteablePaths 3> Warnings.txt

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
        Merge-CIPolicy -PolicyPaths .\WDAC_From_AuditEvents.xml, .\DeletedFilesHashes.XML -OutputFilePath .\SupplementalPolicy.xml

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

        # convert the Supplemental Policy file to .cip binary file
        ConvertFrom-CIPolicy ".\SupplementalPolicy.xml" "$policyID.cip"
        # convert the Base policy file to .cip binary file
        write-host  "This is the GUID of the Base Policy: $BasePolicyID" -ForegroundColor Magenta
        ConvertFrom-CIPolicy .\AllowMicrosoft.xml "$BasePolicyID.cip"
    }

    # Prepare the system for Audit mode using AllowMicrosoft example policy
    $Prep_System_For_MSFT_Only_AuditSCRIPTBLOCK = {
        Copy-Item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\AllowMicrosoft.xml
        Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option 3
        $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
        $PolicyID = $PolicyID.Substring(11)
        ConvertFrom-CIPolicy .\AllowMicrosoft.xml "$PolicyID.cip"
        Move-Item -Path "$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
    }

    # Create WDAC Policy with ISG for Lightly Managed system
    $Create_Lightly_Managed_WDAC_PolicySCRIPTBLOCK = { 
        copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination ".\AllowMicrosoft.xml"
        @(0, 2, 11, 12, 14, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option $_ }
        @(1, 3, 4, 5, 6, 7, 8, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option $_ -Delete }
    
        $BasePolicyID = Set-CiPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
        $BasePolicyID = $BasePolicyID.Substring(11)
            
        Invoke-Command -ScriptBlock $Get_Recommended_Block_RulesSCRIPTBLOCK        
        
        Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, '.\Microsoft recommended block rules.XML' -OutputFilePath .\SignedAndReputable.xml
        
        Set-HVCIOptions -Strict -FilePath .\SignedAndReputable.xml

        Remove-Item .\AllowMicrosoft.xml -Force
        Remove-Item '.\Microsoft recommended block rules.XML' -Force

        Write-Host -NoNewline "This is the PolicyID of the SignedAndReputable.xml:"; Write-Host " $BasePolicyID" -ForegroundColor Magenta
    
    }

    # Deploy WDAC Policy with ISG for Lightly Managed system
    $Deploy_Lightly_Managed_WDAC_PolicySCRIPTBLOCK = {
        Invoke-Command -ScriptBlock $Create_Lightly_Managed_WDAC_PolicySCRIPTBLOCK        
        $xml = [xml](Get-Content .\SignedAndReputable.xml)
        $PolicyID = $xml.SiPolicy.PolicyID
        ConvertFrom-CIPolicy .\SignedAndReputable.xml "$PolicyID.cip"
        Move-Item -Path ".\$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"
    }

    # Sign and deploy a WDAC policy
    $Sign_Deploy_PolicySCRIPTBLOCK = {
        Add-SignerRule -FilePath $WDACPolicyPath -CertificatePath $CertPath -Update -User -Kernel -Supplemental

        Set-HVCIOptions -Strict -FilePath $WDACPolicyPath

        Set-RuleOption -FilePath $WDACPolicyPath -Option 6 -Delete

        $xml = [xml](Get-Content $WDACPolicyPath)
        $PolicyID = $xml.SiPolicy.PolicyID

        ConvertFrom-CIPolicy $WDACPolicyPath "$PolicyID.cip"

        if ($SignToolExePath) {
            $SignToolExePath = $SignToolExePath
        }
        else {

            if ($Env:PROCESSOR_ARCHITECTURE -eq "AMD64") {
                if ( Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe") {
                    $SignToolExePath = "C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe" 
                }
                else {
                    Write-Error "signtool.exe couldn't be found"
                    break
                }
            }
            elseif ($Env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
                if (Test-Path -Path "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe") {
                    $SignToolExePath = "C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe"
                }
                else {
                    Write-Error "signtool.exe couldn't be found"
                    break
                }
            }           
        }
        
        & $SignToolExePath sign -v -n $CertCN -p7 . -p7co 1.3.6.1.4.1.311.79.1 -fd certHash ".\$PolicyID.cip"
              
        Remove-Item ".\$PolicyID.cip" -Force

        try {
            Rename-Item "$PolicyID.cip.p7" -NewName "$PolicyID.cip" -Force -ErrorAction Stop
        }
        catch {
            Write-Error "Certificate with the Common Name $CertCN couldn't be found"
            break
        }

        Copy-Item -Path ".\$PolicyID.cip" -Destination "C:\Windows\System32\CodeIntegrity\CiPolicies\Active"

        $MountPoint = "C:\EFIMount"
        $EFIDestinationFolder = "$MountPoint\EFI\Microsoft\Boot\CiPolicies\Active"
        $EFIPartition = (Get-Partition | Where-Object IsSystem).AccessPaths[0]
        if (-Not (Test-Path $MountPoint)) { New-Item -Path $MountPoint -Type Directory -Force }
        mountvol $MountPoint $EFIPartition
        if (-Not (Test-Path $EFIDestinationFolder)) { New-Item -Path $EFIDestinationFolder -Type Directory -Force }

        Copy-Item -Path ".\$PolicyID.cip" -Destination $EFIDestinationFolder -Force

        Remove-Item "C:\EFIMount" -Recurse -Force    
    }

    #endregion Script-Blocks

    #region function-processing
    if ($Get_Recommended_Block_Rules) {              
        Invoke-Command -ScriptBlock $Get_Recommended_Block_RulesSCRIPTBLOCK
    }                                
    if ($Get_Recommended_Driver_Block_Rules) {
        Invoke-Command -ScriptBlock $Get_Recommended_Driver_Block_RulesSCRIPTBLOCK
    }   
    if ($Create_AllowMicrosoft_With_Rec_BlockRules) {
        Invoke-Command -ScriptBlock $Create_AllowMicrosoft_With_Rec_BlockRulesSCRIPTBLOCK
    }
    if ($Deploy_AllowMicrosoft_With_Rec_BlockRules) {
        Invoke-Command -ScriptBlock $Deploy_AllowMicrosoft_With_Rec_BlockRulesSCRIPTBLOCK
    }
    if ($Deploy_Latest_Driver_BlockRules) {
        Invoke-Command -ScriptBlock $Deploy_Latest_Driver_BlockRulesSCRIPTBLOCK
    }                               
    if ($Create_Scheduled_Task_Auto_Driver_BlockRules_Update) {
        Invoke-Command -ScriptBlock $Create_Scheduled_Task_Auto_Driver_BlockRules_UpdateSCRIPTBLOCK
    }                                
    if ($Create_WDAC_Policy_From_Audit_Logs) {
        Invoke-Command -ScriptBlock $Create_WDAC_Policy_From_Audit_LogsSCRIPTBLOCK
    }                                
    if ($Prep_System_For_MSFT_Only_Audit) {
        Invoke-Command -ScriptBlock $Prep_System_For_MSFT_Only_AuditSCRIPTBLOCK
    }
    if ($Create_Lightly_Managed_WDAC_Policy) {
        Invoke-Command -ScriptBlock $Create_Lightly_Managed_WDAC_PolicySCRIPTBLOCK
    }
    if ($Deploy_Lightly_Managed_WDAC_Policy) {
        Invoke-Command -ScriptBlock $Deploy_Lightly_Managed_WDAC_PolicySCRIPTBLOCK
    }
    if ($Sign_Deploy_Policy) {
        Invoke-Command -ScriptBlock $Sign_Deploy_PolicySCRIPTBLOCK
    }
    #endregion function-processing
}
