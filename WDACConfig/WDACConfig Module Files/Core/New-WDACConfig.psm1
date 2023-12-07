function New-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = 'Get Block Rules',
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        # 9 Main parameters - should be used for position 0
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Block Rules')][System.Management.Automation.SwitchParameter]$GetBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Driver Block Rules')][System.Management.Automation.SwitchParameter]$GetDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')][System.Management.Automation.SwitchParameter]$MakeAllowMSFTWithBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Set Auto Update Driver Block Rules')][System.Management.Automation.SwitchParameter]$SetAutoUpdateDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep MSFT Only Audit')][System.Management.Automation.SwitchParameter]$PrepMSFTOnlyAudit,
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep Default Windows Audit')][System.Management.Automation.SwitchParameter]$PrepDefaultWindowsAudit,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')][System.Management.Automation.SwitchParameter]$MakePolicyFromAuditLogs,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')][System.Management.Automation.SwitchParameter]$MakeLightPolicy,
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')][System.Management.Automation.SwitchParameter]$MakeDefaultWindowsWithBlockRules,

        [ValidateSet('Allow Microsoft Base', 'Default Windows Base')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String]$BasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep MSFT Only Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep Default Windows Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Get Driver Block Rules')]
        [System.Management.Automation.SwitchParameter]$Deploy,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.Management.Automation.SwitchParameter]$IncludeSignTool,

        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.String]$SignToolPath,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.Management.Automation.SwitchParameter]$TestMode,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make AllowMSFT With Block Rules')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Light Policy')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make DefaultWindows With Block Rules')]
        [System.Management.Automation.SwitchParameter]$RequireEVSigners,

        [ValidateSet('OriginalFileName', 'InternalName', 'FileDescription', 'ProductName', 'PackageFamilyName', 'FilePath')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Management.Automation.SwitchParameter]$NoDeletedFiles,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Management.Automation.SwitchParameter]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Management.Automation.SwitchParameter]$NoScript,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String]$Level = 'FilePublisher', # Setting the default value for the Level parameter

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.String[]]$Fallbacks = 'Hash', # Setting the default value for the Fallbacks parameter

        # Setting the maxim range to the maximum allowed log size by Windows Event viewer
        [ValidateRange(1024KB, 18014398509481983KB)]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep MSFT Only Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Prep Default Windows Audit')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Make Policy From Audit Logs')]
        [System.Int64]$LogSize,

        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SkipVersionCheck
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$ModuleRootPath\Resources\Resources.ps1"

        # Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'

        # Fetching Temp Directory
        [System.String]$global:UserTempDirectoryPath = [System.IO.Path]::GetTempPath()

        # Fetch User account directory path
        [System.String]$global:UserAccountDirectoryPath = (Get-CimInstance Win32_UserProfile -Filter "SID = '$([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)'").LocalPath

        #region User-Configurations-Processing-Validation
        # If User is creating Default Windows policy and including SignTool path
        if ($IncludeSignTool -and $MakeDefaultWindowsWithBlockRules) {
            # Read User configuration file if it exists
            $UserConfig = Get-Content -Path "$global:UserAccountDirectoryPath\.WDACConfig\UserConfigurations.json" -ErrorAction SilentlyContinue
            if ($UserConfig) {
                # Validate the Json file and read its content to make sure it's not corrupted
                try { $UserConfig = $UserConfig | ConvertFrom-Json }
                catch {
                    Write-Error -Message 'User Configurations Json file is corrupted, deleting it...' -ErrorAction Continue
                    # Calling this function with this parameter automatically does its job and breaks/stops the operation
                    Set-CommonWDACConfig -DeleteUserConfig
                }
            }
        }

        # Get SignToolPath from user parameter or user config file or auto-detect it
        if ($SignToolPath) {
            $SignToolPathFinal = Get-SignTool -SignToolExePath $SignToolPath
        } # If it is null, then Get-SignTool will behave the same as if it was called without any arguments.
        elseif ($IncludeSignTool -and $MakeDefaultWindowsWithBlockRules) {
            $SignToolPathFinal = Get-SignTool -SignToolExePath ($UserConfig.SignToolCustomPath ?? $null)
        }
        #endregion User-Configurations-Processing-Validation

        # Detecting if Debug switch is used, will do debugging actions based on that
        $PSBoundParameters.Debug.IsPresent ? ([System.Boolean]$Debug = $true) : ([System.Boolean]$Debug = $false) | Out-Null

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

        [System.Management.Automation.ScriptBlock]$GetDriverBlockRulesSCRIPTBLOCK = {
            [System.String]$DriverRules = (Invoke-WebRequest -Uri $MSFTRecommendeDriverBlockRulesURL -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1'
            # Remove the unnecessary rules and elements - not using this one because then during the merge there will be error - The reason is that "<FileRuleRef RuleID="ID_ALLOW_ALL_2" />" is the only FileruleRef in the xml and after removing it, the <SigningScenario> element will be empty
            $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_[12]"\sFriendlyName=""\sFileName="\*".*/>', ''
            $DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_1".*/>', ''
            $DriverRules = $DriverRules -replace '<SigningScenario\sValue="12"\sID="ID_SIGNINGSCENARIO_WINDOWS"\sFriendlyName="Auto\sgenerated\spolicy[\S\s]*<\/SigningScenario>', ''
            $DriverRules | Out-File 'Microsoft recommended driver block rules TEMP.xml'
            # Remove empty lines from the policy file
            Get-Content -Path 'Microsoft recommended driver block rules TEMP.xml' | Where-Object -FilterScript { $_.trim() -ne '' } | Out-File 'Microsoft recommended driver block rules.xml'
            Remove-Item -Path 'Microsoft recommended driver block rules TEMP.xml' -Force
            Set-RuleOption -FilePath 'Microsoft recommended driver block rules.xml' -Option 3 -Delete
            Set-HVCIOptions -Strict -FilePath 'Microsoft recommended driver block rules.xml'
            # Display extra info about the Microsoft Drivers block list
            Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
            # Display the result as object
            [PSCustomObject]@{
                PolicyFile = 'Microsoft recommended driver block rules.xml'
            }
        }

        [System.Management.Automation.ScriptBlock]$MakeAllowMSFTWithBlockRulesSCRIPTBLOCK = {

            param([System.Boolean]$NoCIP)
            # Get the latest Microsoft recommended block rules
            Invoke-Command -ScriptBlock $GetBlockRulesSCRIPTBLOCK | Out-Null
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml' -Destination 'AllowMicrosoft.xml'
            Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\AllowMicrosoftPlusBlockRules.xml | Out-Null
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoftPlusBlockRules.xml -PolicyName "Allow Microsoft Plus Block Rules - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath .\AllowMicrosoftPlusBlockRules.xml -Version '1.0.0.0'
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ }
            @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ -Delete }
            if ($TestMode -and $MakeAllowMSFTWithBlockRules) {
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ }
            }
            if ($RequireEVSigners -and $MakeAllowMSFTWithBlockRules) {
                Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option 8
            }
            Set-HVCIOptions -Strict -FilePath .\AllowMicrosoftPlusBlockRules.xml
            ConvertFrom-CIPolicy -XmlFilePath .\AllowMicrosoftPlusBlockRules.xml -BinaryFilePath "$PolicyID.cip" | Out-Null
            # Remove the extra files that were created during module operation and are no longer needed
            Remove-Item -Path '.\AllowMicrosoft.xml', 'Microsoft recommended block rules.xml' -Force
            [PSCustomObject]@{
                PolicyFile = 'AllowMicrosoftPlusBlockRules.xml'
                BinaryFile = "$PolicyID.cip"
            }
            if ($Deploy -and $MakeAllowMSFTWithBlockRules) {
                CiTool --update-policy "$PolicyID.cip" -json | Out-Null
                Write-Host -Object "`n"
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            if ($NoCIP)
            { Remove-Item -Path "$PolicyID.cip" -Force }
        }

        [System.Management.Automation.ScriptBlock]$MakeDefaultWindowsWithBlockRulesSCRIPTBLOCK = {
            param([System.Boolean]$NoCIP)
            Invoke-Command -ScriptBlock $GetBlockRulesSCRIPTBLOCK | Out-Null
            Copy-Item -Path 'C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml' -Destination 'DefaultWindows_Enforced.xml'

            [System.Boolean]$global:MergeSignToolPolicy = $false

            if ($SignToolPathFinal) {
                # Allowing SignTool to be able to run after Default Windows base policy is deployed in Signed scenario
                &$WriteTeaGreen "`nCreating allow rules for SignTool.exe in the DefaultWindows base policy so you can continue using it after deploying the DefaultWindows base policy."
                New-Item -Path "$global:UserTempDirectoryPath\TemporarySignToolFile" -ItemType Directory -Force | Out-Null
                Copy-Item -Path $SignToolPathFinal -Destination "$global:UserTempDirectoryPath\TemporarySignToolFile" -Force
                New-CIPolicy -ScanPath "$global:UserTempDirectoryPath\TemporarySignToolFile" -Level FilePublisher -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -AllowFileNameFallbacks -FilePath .\SignTool.xml
                # Delete the Temporary folder in the TEMP folder
                if (!$Debug) { Remove-Item -Recurse -Path "$global:UserTempDirectoryPath\TemporarySignToolFile" -Force }

                [System.Boolean]$global:MergeSignToolPolicy = $true
            }

            # Scan PowerShell core directory and allow its files in the Default Windows base policy so that module can still be used once it's been deployed
            if (Test-Path -Path 'C:\Program Files\PowerShell') {
                &$WriteLavender 'Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it.'
                New-CIPolicy -ScanPath 'C:\Program Files\PowerShell' -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml

                if ($global:MergeSignToolPolicy) {
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, 'Microsoft recommended block rules.xml', .\SignTool.xml -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
                else {
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
            }
            else {
                if ($global:MergeSignToolPolicy) {
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, 'Microsoft recommended block rules.xml', .\SignTool.xml -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
                else {
                    Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
                }
            }

            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\DefaultWindowsPlusBlockRules.xml -PolicyName "Default Windows Plus Block Rules - $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath .\DefaultWindowsPlusBlockRules.xml -Version '1.0.0.0'
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ }
            @(3, 4, 9, 10, 13, 18) | ForEach-Object -Process { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ -Delete }
            if ($TestMode -and $MakeDefaultWindowsWithBlockRules) {
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ }
            }
            if ($RequireEVSigners -and $MakeDefaultWindowsWithBlockRules) {
                Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option 8
            }
            Set-HVCIOptions -Strict -FilePath .\DefaultWindowsPlusBlockRules.xml
            ConvertFrom-CIPolicy -XmlFilePath .\DefaultWindowsPlusBlockRules.xml -BinaryFilePath "$PolicyID.cip" | Out-Null

            Remove-Item -Path .\AllowPowerShell.xml -Force -ErrorAction SilentlyContinue
            Remove-Item -Path '.\DefaultWindows_Enforced.xml', 'Microsoft recommended block rules.xml' -Force
            if ($global:MergeSignToolPolicy -and !$Debug) { Remove-Item -Path .\SignTool.xml -Force }

            [PSCustomObject]@{
                PolicyFile = 'DefaultWindowsPlusBlockRules.xml'
                BinaryFile = "$PolicyID.cip"
            }

            if ($Deploy -and $MakeDefaultWindowsWithBlockRules) {
                CiTool --update-policy "$PolicyID.cip" -json | Out-Null
                Write-Host -Object "`n"
                Remove-Item -Path "$PolicyID.cip" -Force
            }
            if ($NoCIP) { Remove-Item -Path "$PolicyID.cip" -Force }
        }

        [System.Management.Automation.ScriptBlock]$DeployLatestDriverBlockRulesSCRIPTBLOCK = {
            Invoke-WebRequest -Uri 'https://aka.ms/VulnerableDriverBlockList' -OutFile VulnerableDriverBlockList.zip -ProgressAction SilentlyContinue
            Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath 'VulnerableDriverBlockList' -Force
            Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName 'SiPolicy.p7b' -Force
            Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination 'C:\Windows\System32\CodeIntegrity'
            citool --refresh -json | Out-Null
            &$WritePink 'SiPolicy.p7b has been deployed and policies refreshed.'
            Remove-Item -Path .\VulnerableDriverBlockList* -Recurse -Force
            Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
        }

        [System.Management.Automation.ScriptBlock]$DeployLatestBlockRulesSCRIPTBLOCK = {
            (Invoke-WebRequest -Uri $MSFTRecommendeBlockRulesURL -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1' | Out-File '.\Microsoft recommended block rules TEMP.xml'
            # Remove empty lines from the policy file
            Get-Content -Path '.\Microsoft recommended block rules TEMP.xml' | Where-Object -FilterScript { $_.trim() -ne '' } | Out-File '.\Microsoft recommended block rules.xml'
            Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option 3 -Delete
            @(0, 2, 6, 11, 12, 16, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option $_ }
            Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.xml'
            Remove-Item -Path '.\Microsoft recommended block rules TEMP.xml' -Force
            [System.String]$PolicyID = (Set-CIPolicyIdInfo -FilePath '.\Microsoft recommended block rules.xml' -ResetPolicyID).Substring(11)
            Set-CIPolicyIdInfo -PolicyName "Microsoft Windows User Mode Policy - Enforced - $(Get-Date -Format 'MM-dd-yyyy')" -FilePath '.\Microsoft recommended block rules.xml'
            ConvertFrom-CIPolicy -XmlFilePath '.\Microsoft recommended block rules.xml' -BinaryFilePath "$PolicyID.cip" | Out-Null
            CiTool --update-policy "$PolicyID.cip" -json | Out-Null
            &$WriteLavender 'The Microsoft recommended block rules policy has been deployed in enforced mode.'
            Remove-Item -Path "$PolicyID.cip" -Force
        }

        [System.Management.Automation.ScriptBlock]$SetAutoUpdateDriverBlockRulesSCRIPTBLOCK = {
            # create a scheduled task that runs every 7 days
            if (-NOT (Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath '\MSFT Driver Block list update\' -ErrorAction SilentlyContinue)) {
                # Get the SID of the SYSTEM account. It is a well-known SID, but still querying it, going to use it to create the scheduled task
                $SYSTEMSID = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
                # create a scheduled task that runs every 7 days
                $Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                    -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit};Expand-Archive .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "C:\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item .\VulnerableDriverBlockList -Recurse -Force;Remove-Item .\VulnerableDriverBlockList.zip -Force;}"'
                $TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId $($SYSTEMSID.Value) -RunLevel Highest
                # trigger
                $Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)
                # register the task
                Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update'
                # define advanced settings for the task
                $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility Win8 -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3)
                # add advanced settings we defined to the task
                Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings
            }
            Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK
        }

        [System.Management.Automation.ScriptBlock]$PrepMSFTOnlyAuditSCRIPTBLOCK = {
            if ($PrepMSFTOnlyAudit -and $LogSize) { Set-LogSize -LogSize $LogSize }
            Copy-Item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\AllowMicrosoft.xml
            Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option 3
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyIdInfo -PolicyName 'PrepMSFTOnlyAudit' -FilePath .\AllowMicrosoft.xml
            ConvertFrom-CIPolicy -XmlFilePath .\AllowMicrosoft.xml -BinaryFilePath "$PolicyID.cip" | Out-Null
            if ($Deploy) {
                CiTool --update-policy "$PolicyID.cip" -json | Out-Null
                &$WriteHotPink 'The default AllowMicrosoft policy has been deployed in Audit mode. No reboot required.'
                Remove-Item -Path 'AllowMicrosoft.xml', "$PolicyID.cip" -Force
            }
            else {
                &$WriteHotPink 'The default AllowMicrosoft policy has been created in Audit mode and is ready for deployment.'
            }
        }

        [System.Management.Automation.ScriptBlock]$PrepDefaultWindowsAuditSCRIPTBLOCK = {
            if ($PrepDefaultWindowsAudit -and $LogSize) { Set-LogSize -LogSize $LogSize }
            Copy-Item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml -Destination .\DefaultWindows_Audit.xml -Force

            # Making Sure neither PowerShell core nor WDACConfig module files are added to the Supplemental policy created by -MakePolicyFromAuditLogs parameter
            # by adding them first to the deployed Default Windows policy in Audit mode. Because WDACConfig module files don't need to be allowed to run since they are *.ps1 and .*psm1 files
            # And PowerShell core files will be added to the DefaultWindows Base policy anyway
            if (Test-Path -Path 'C:\Program Files\PowerShell') {
                New-CIPolicy -ScanPath 'C:\Program Files\PowerShell' -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml
                New-CIPolicy -ScanPath "$ModuleRootPath" -Level hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\WDACConfigModule.xml
                Merge-CIPolicy -PolicyPaths .\DefaultWindows_Audit.xml, .\AllowPowerShell.xml, .\WDACConfigModule.xml -OutputFilePath .\DefaultWindows_Audit_temp.xml | Out-Null

                Remove-Item -Path DefaultWindows_Audit.xml -Force
                Rename-Item -Path .\DefaultWindows_Audit_temp.xml -NewName 'DefaultWindows_Audit.xml' -Force
                Remove-Item -Path 'WDACConfigModule.xml', 'AllowPowerShell.xml' -Force
            }

            Set-RuleOption -FilePath .\DefaultWindows_Audit.xml -Option 3
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath .\DefaultWindows_Audit.xml -ResetPolicyID
            [System.String]$PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyIdInfo -PolicyName 'PrepDefaultWindows' -FilePath .\DefaultWindows_Audit.xml
            ConvertFrom-CIPolicy -XmlFilePath .\DefaultWindows_Audit.xml -BinaryFilePath "$PolicyID.cip" | Out-Null
            if ($Deploy) {
                CiTool --update-policy "$PolicyID.cip" -json | Out-Null
                &$WriteLavender 'The defaultWindows policy has been deployed in Audit mode. No reboot required.'
                Remove-Item -Path 'DefaultWindows_Audit.xml', "$PolicyID.cip" -Force
            }
            else {
                &$WriteLavender 'The defaultWindows policy has been created in Audit mode and is ready for deployment.'
            }
        }

        [System.Management.Automation.ScriptBlock]$MakePolicyFromAuditLogsSCRIPTBLOCK = {
            if ($MakePolicyFromAuditLogs -and $LogSize) { Set-LogSize -LogSize $LogSize }
            # Make sure there is no leftover files from previous operations of this same command
            Remove-Item -Path "$home\WDAC\*" -Recurse -Force -ErrorAction SilentlyContinue
            # Create a working directory in user's folder
            New-Item -Type Directory -Path "$home\WDAC" -Force | Out-Null
            Set-Location "$home\WDAC"

            ############################### Base Policy Processing ###############################

            switch ($BasePolicyType) {
                'Allow Microsoft Base' {
                    Invoke-Command -ScriptBlock $MakeAllowMSFTWithBlockRulesSCRIPTBLOCK | Out-Null
                    $xml = [System.Xml.XmlDocument](Get-Content -Path .\AllowMicrosoftPlusBlockRules.xml)
                    $BasePolicyID = $xml.SiPolicy.PolicyID
                    # define the location of the base policy
                    $BasePolicy = 'AllowMicrosoftPlusBlockRules.xml'
                }
                'Default Windows Base' {
                    Invoke-Command -ScriptBlock $MakeDefaultWindowsWithBlockRulesSCRIPTBLOCK | Out-Null
                    $xml = [System.Xml.XmlDocument](Get-Content -Path .\DefaultWindowsPlusBlockRules.xml)
                    $BasePolicyID = $xml.SiPolicy.PolicyID
                    # define the location of the base policy
                    $BasePolicy = 'DefaultWindowsPlusBlockRules.xml'
                }
            }
            if ($TestMode -and $MakePolicyFromAuditLogs) {
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath $BasePolicy -Option $_ }
            }
            if ($RequireEVSigners -and $MakePolicyFromAuditLogs) {
                Set-RuleOption -FilePath $BasePolicy -Option 8
            }

            ############################### Supplemental Processing ###############################

            # Produce a policy xml file from event viewer logs
            &$WriteLavender 'Scanning Windows Event logs and creating a policy file, please wait...'

            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                FilePath               = 'AuditLogsPolicy_NoDeletedFiles.xml'
                Audit                  = $true
                Level                  = $Level
                Fallback               = $Fallbacks
                MultiplePolicyFormat   = $true
                UserWriteablePaths     = $true
                WarningAction          = 'SilentlyContinue'
                AllowFileNameFallbacks = $true
            }
            # Assess user input parameters and add the required parameters to the hash table
            if ($SpecificFileNameLevel) { $PolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }
            if ($NoScript) { $PolicyMakerHashTable['NoScript'] = $true }
            if (!$NoUserPEs) { $PolicyMakerHashTable['UserPEs'] = $true }

            &$WriteHotPink "`nGenerating Supplemental policy with the following specifications:"
            $PolicyMakerHashTable
            Write-Host -Object "`n"
            # Create the supplemental policy via parameter splatting for files in event viewer that are currently on the disk
            New-CIPolicy @PolicyMakerHashTable

            if (!$NoDeletedFiles) {
                # Get Event viewer logs for code integrity - check the file path of all of the files in the log, resolve them using the command above - show files that are no longer available on the disk
                [System.Management.Automation.ScriptBlock]$AuditEventLogsDeletedFilesScriptBlock = {
                    foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 }) {
                        $xml = [System.Xml.XmlDocument]$event.toxml()
                        $xml.event.eventdata.data |
                        ForEach-Object -Begin { $Hash = @{} } -Process { $hash[$_.name] = $_.'#text' } -End { [pscustomobject]$hash } |
                        ForEach-Object -Process {
                            if ($_.'File Name' -match ($pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$')) {
                                $hardDiskVolumeNumber = $Matches[1]
                                $remainingPath = $Matches[2]
                                $getletter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$hardDiskVolumeNumber" }
                                $usablePath = "$($getletter.DriveLetter)$remainingPath"
                                $_.'File Name' = $_.'File Name' -replace $pattern, $usablePath
                            }
                            if (-NOT (Test-Path -Path $_.'File Name')) {
                                $_ | Select-Object FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                            }
                        }
                    }
                }
                # storing the output from the scriptblock above in a variable
                $DeletedFileHashesArray = Invoke-Command -ScriptBlock $AuditEventLogsDeletedFilesScriptBlock
            }
            # run the following only if there are any event logs for files no longer on the disk and if -NoDeletedFiles switch parameter wasn't used
            if ($DeletedFileHashesArray -and !$NoDeletedFiles) {

                # Save the the File Rules and File Rule Refs to the Out-File FileRulesAndFileRefs.txt in the current working directory
                (Get-FileRules -HashesArray $DeletedFileHashesArray) + (Get-RuleRefs -HashesArray $DeletedFileHashesArray) | Out-File FileRulesAndFileRefs.txt

                # Put the Rules and RulesRefs in an empty policy file
                New-EmptyPolicy -RulesContent (Get-FileRules -HashesArray $DeletedFileHashesArray) -RuleRefsContent (Get-RuleRefs -HashesArray $DeletedFileHashesArray) | Out-File .\DeletedFilesHashes.xml

                # Merge the policy file we created at first using Event Viewer logs, with the policy file we created for Hash of the files no longer available on the disk
                Merge-CIPolicy -PolicyPaths 'AuditLogsPolicy_NoDeletedFiles.xml', .\DeletedFilesHashes.xml -OutputFilePath .\SupplementalPolicy.xml | Out-Null
            }
            # do this only if there are no event logs detected with files no longer on the disk, so we use the policy file created earlier using Audit even logs
            else {
                Rename-Item -Path 'AuditLogsPolicy_NoDeletedFiles.xml' -NewName 'SupplementalPolicy.xml' -Force
            }
            # Convert the SupplementalPolicy.xml policy file from base policy to supplemental policy of our base policy
            Set-CIPolicyVersion -FilePath 'SupplementalPolicy.xml' -Version '1.0.0.0'
            [System.String]$PolicyID = Set-CIPolicyIdInfo -FilePath 'SupplementalPolicy.xml' -PolicyName "Supplemental Policy made from Audit Event Logs on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $BasePolicy
            [System.String]$PolicyID = $PolicyID.Substring(11)
            # Make sure policy rule options that don't belong to a Supplemental policy don't exit
            @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object -Process { Set-RuleOption -FilePath 'SupplementalPolicy.xml' -Option $_ -Delete }

            # Set the hypervisor Code Integrity option for Supplemental policy to Strict
            Set-HVCIOptions -Strict -FilePath 'SupplementalPolicy.xml'
            # convert the Supplemental Policy file to .cip binary file
            ConvertFrom-CIPolicy -XmlFilePath 'SupplementalPolicy.xml' -BinaryFilePath "$policyID.cip" | Out-Null

            [PSCustomObject]@{
                BasePolicyFile = $BasePolicy
                BasePolicyGUID = $BasePolicyID
            }
            [PSCustomObject]@{
                SupplementalPolicyFile = 'SupplementalPolicy.xml'
                SupplementalPolicyGUID = $PolicyID
            }

            if (-NOT $Debug) {
                Remove-Item -Path 'AuditLogsPolicy_NoDeletedFiles.xml', 'FileRulesAndFileRefs.txt', 'DeletedFilesHashes.xml' -Force -ErrorAction SilentlyContinue
            }

            if ($Deploy -and $MakePolicyFromAuditLogs) {
                CiTool --update-policy "$BasePolicyID.cip" -json | Out-Null
                CiTool --update-policy "$policyID.cip" -json | Out-Null
                &$WritePink "`nBase policy and Supplemental Policies deployed and activated.`n"
                # Get the correct Prep mode Audit policy ID to remove from the system
                switch ($BasePolicyType) {
                    'Allow Microsoft Base' {
                        $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.FriendlyName -eq 'PrepMSFTOnlyAudit' }).PolicyID
                    }
                    'Default Windows Base' {
                        $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { $_.FriendlyName -eq 'PrepDefaultWindows' }).PolicyID
                    }
                }
                CiTool --remove-policy "{$IDToRemove}" -json | Out-Null
                &$WriteLavender "`nSystem restart required to finish removing the Audit mode Prep policy"
            }
        }

        [System.Management.Automation.ScriptBlock]$MakeLightPolicySCRIPTBLOCK = {
            # Delete the any policy with the same name in the current working directory
            Remove-Item -Path 'SignedAndReputable.xml' -Force -ErrorAction SilentlyContinue
            Invoke-Command -ScriptBlock $MakeAllowMSFTWithBlockRulesSCRIPTBLOCK -ArgumentList $true | Out-Null
            Rename-Item -Path 'AllowMicrosoftPlusBlockRules.xml' -NewName 'SignedAndReputable.xml' -Force
            @(14, 15) | ForEach-Object -Process { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }
            if ($TestMode -and $MakeLightPolicy) {
                9..10 | ForEach-Object -Process { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }
            }
            if ($RequireEVSigners -and $MakeLightPolicy) {
                Set-RuleOption -FilePath .\SignedAndReputable.xml -Option 8
            }
            $BasePolicyID = Set-CIPolicyIdInfo -FilePath .\SignedAndReputable.xml -ResetPolicyID -PolicyName "Signed And Reputable policy - $(Get-Date -Format 'MM-dd-yyyy')"
            $BasePolicyID = $BasePolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath .\SignedAndReputable.xml -Version '1.0.0.0'
            Set-HVCIOptions -Strict -FilePath .\SignedAndReputable.xml
            ConvertFrom-CIPolicy -XmlFilePath .\SignedAndReputable.xml -BinaryFilePath "$BasePolicyID.cip" | Out-Null
            # Configure required services for ISG authorization
            Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -Wait -NoNewWindow
            Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', 'start= auto' -Wait -NoNewWindow
            if ($Deploy -and $MakeLightPolicy) {
                CiTool --update-policy "$BasePolicyID.cip" -json | Out-Null
            }
            [PSCustomObject]@{
                BasePolicyFile = 'SignedAndReputable.xml'
                BasePolicyGUID = $BasePolicyID
            }
        }

        # Script block that is used to supply extra information regarding Microsoft recommended driver block rules in commands that use them
        [System.Management.Automation.ScriptBlock]$DriversBlockListInfoGatheringSCRIPTBLOCK = {
            [System.String]$owner = 'MicrosoftDocs'
            [System.String]$repo = 'windows-itpro-docs'
            [System.String]$path = 'windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md'

            [System.String]$ApiUrl = "https://api.github.com/repos/$owner/$repo/commits?path=$path"
            [System.Object[]]$Response = Invoke-RestMethod -Uri $ApiUrl -ProgressAction SilentlyContinue
            [System.DateTime]$Date = $Response[0].commit.author.date

            &$WriteLavender "The document containing the drivers block list on GitHub was last updated on $Date"
            [System.String]$MicrosoftRecommendeDriverBlockRules = (Invoke-WebRequest -Uri $MSFTRecommendeDriverBlockRulesURL -ProgressAction SilentlyContinue).Content
            $MicrosoftRecommendeDriverBlockRules -match '<VersionEx>(.*)</VersionEx>' | Out-Null
            &$WritePink "The current version of Microsoft recommended drivers block list is $($Matches[1])"
        }

        if (-NOT $SkipVersionCheck) { . Update-self }

        $DriveLettersGlobalRootFix = Invoke-Command -ScriptBlock $DriveLettersGlobalRootFixScriptBlock
    }

    process {

        switch ($true) {
            # Deploy the latest block rules
            { $GetBlockRules -and $Deploy } { & $DeployLatestBlockRulesSCRIPTBLOCK; break }
            # Get the latest block rules
            $GetBlockRules { & $GetBlockRulesSCRIPTBLOCK; break }
            # Deploy the latest driver block rules
            { $GetDriverBlockRules -and $Deploy } { & $DeployLatestDriverBlockRulesSCRIPTBLOCK; break }
            # Get the latest driver block rules
            { $GetDriverBlockRules } { & $GetDriverBlockRulesSCRIPTBLOCK; break }

            $SetAutoUpdateDriverBlockRules { & $SetAutoUpdateDriverBlockRulesSCRIPTBLOCK; break }
            $MakeAllowMSFTWithBlockRules { & $MakeAllowMSFTWithBlockRulesSCRIPTBLOCK; break }
            $MakePolicyFromAuditLogs { & $MakePolicyFromAuditLogsSCRIPTBLOCK; break }
            $PrepMSFTOnlyAudit { & $PrepMSFTOnlyAuditSCRIPTBLOCK; break }
            $MakeLightPolicy { & $MakeLightPolicySCRIPTBLOCK; break }
            $MakeDefaultWindowsWithBlockRules { & $MakeDefaultWindowsWithBlockRulesSCRIPTBLOCK; break }
            $PrepDefaultWindowsAudit { & $PrepDefaultWindowsAuditSCRIPTBLOCK; break }
            default { Write-Warning 'None of the main parameters were selected.'; break }
        }
    }

    <#
.SYNOPSIS
    Automate a lot of tasks related to WDAC (Windows Defender Application Control)

.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/New-WDACConfig

.DESCRIPTION
    Using official Microsoft methods, configure and use Windows Defender Application Control

.COMPONENT
    Windows Defender Application Control, ConfigCI PowerShell module

.FUNCTIONALITY
    Automate various tasks related to Windows Defender Application Control (WDAC)

.PARAMETER GetBlockRules
    Create Microsoft recommended block rules xml policy and remove the allow rules

.PARAMETER GetDriverBlockRules
    Create Microsoft recommended driver block rules xml policy and remove the allow rules

.PARAMETER MakeAllowMSFTWithBlockRules
    Make WDAC policy by merging AllowMicrosoft policy with the recommended block rules

.PARAMETER SetAutoUpdateDriverBlockRules
    Make a Scheduled Task that automatically runs every 7 days to download the newest Microsoft Recommended driver block rules

.PARAMETER PrepMSFTOnlyAudit
    Prepare the system for Audit mode using AllowMicrosoft default policy

.PARAMETER PrepDefaultWindowsAudit
    Prepare the system for Audit mode using DefaultWindows policy

.PARAMETER MakePolicyFromAuditLogs
    Make a WDAC Policy from Audit event logs that also covers files no longer on disk

.PARAMETER MakeLightPolicy
    Make a WDAC Policy with ISG for Lightly Managed system

.PARAMETER MakeDefaultWindowsWithBlockRules
    Make a WDAC policy by merging DefaultWindows policy with the recommended block rules

.PARAMETER BasePolicyType
    Select the Base Policy Type

.PARAMETER Deploy
    Deploys the policy that is being created

.PARAMETER IncludeSignTool
    Indicates that the Default Windows policy that is being created must include Allow rules for SignTool.exe - This parameter must be used when you intend to Sign and Deploy the Default Windows policy.

.PARAMETER SignToolPath
    Path to the SignTool.exe file - Optional

.PARAMETER TestMode
    Indicates that the created/deployed policy will have Enabled:Boot Audit on Failure and Enabled:Advanced Boot Options Menu policy rule options

.PARAMETER RequireEVSigners
    Indicates that the created/deployed policy will have Require EV Signers policy rule option.

.PARAMETER NoDeletedFiles
    Indicates that files that were run during program installations but then were deleted and are no longer on the disk, won't be added to the supplemental policy. This can mean the programs you installed will be allowed to run but installation/reinstallation might not be allowed once the policies are deployed.

.PARAMETER SpecificFileNameLevel
    You can choose one of the following options: "OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath". More info available on Microsoft Learn

.PARAMETER NoUserPEs
    By default, the module includes user PEs in the scan. When you use this switch parameter, they won't be included.

.PARAMETER NoScript
    Won't scan script files

.PARAMETER Level
    Offers the same official Levels for scanning of event logs. If no level is specified the default, which is set to FilePublisher in this module, will be used.

.PARAMETER Fallbacks
    Offers the same official Fallbacks for scanning of event logs. If no fallbacks are specified the default, which is set to Hash in this module, will be used.

.PARAMETER LogSize
    Specifies the log size for Microsoft-Windows-CodeIntegrity/Operational events. The values must be in the form of <Digit + Data measurement unit>. e.g., 2MB, 10MB, 1GB, 1TB. The minimum accepted value is 1MB which is the default.

.PARAMETER SkipVersionCheck
    Can be used with any parameter to bypass the online version check - only to be used in rare cases

#>
}

# Importing argument completer ScriptBlocks
. "$ModuleRootPath\Resources\ArgumentCompleters.ps1"
# Set PSReadline tab completion to complete menu for easier access to available parameters - Only for the current session
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Register-ArgumentCompleter -CommandName 'New-WDACConfig' -ParameterName 'SignToolPath' -ScriptBlock $ArgumentCompleterExeFilePathsPicker
