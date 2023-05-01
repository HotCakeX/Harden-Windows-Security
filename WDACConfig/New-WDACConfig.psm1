#Requires -RunAsAdministrator
function New-WDACConfig {
    [CmdletBinding(
        DefaultParameterSetName = "Get Block Rules",
        SupportsShouldProcess = $true,
        PositionalBinding = $false,
        ConfirmImpact = 'High'
    )]
    Param(
        # 11 Main parameters - should be used for position 0
        [Parameter(Mandatory = $false, ParameterSetName = "Get Block Rules")][Switch]$GetBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "Get Driver Block Rules")][Switch]$GetDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "Make AllowMSFT With Block Rules")][Switch]$MakeAllowMSFTWithBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "Deploy Latest Driver Block Rules")][Switch]$DeployLatestDriverBlockRules,                                                                                       
        [Parameter(Mandatory = $false, ParameterSetName = "Set Auto Update Driver Block Rules")][Switch]$SetAutoUpdateDriverBlockRules,
        [Parameter(Mandatory = $false, ParameterSetName = "Prep MSFT Only Audit")][Switch]$PrepMSFTOnlyAudit,
        [Parameter(Mandatory = $false, ParameterSetName = "Prep Default Windows Audit")][Switch]$PrepDefaultWindowsAudit,        
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")][Switch]$MakePolicyFromAuditLogs,  
        [Parameter(Mandatory = $false, ParameterSetName = "Make Light Policy")][Switch]$MakeLightPolicy,
        [Parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")][Switch]$MakeSupplementalPolicy,
        [Parameter(Mandatory = $false, ParameterSetName = "Make DefaultWindows With Block Rules")][Switch]$MakeDefaultWindowsWithBlockRules,
       
        [ValidateScript({ Test-Path $_ -PathType 'Container' }, ErrorMessage = "The path you selected is not a folder path.")]
        [parameter(Mandatory = $true, ParameterSetName = "Make Supplemental Policy", ValueFromPipelineByPropertyName = $true)]
        [System.String]$ScanLocation,

        [parameter(Mandatory = $true, ParameterSetName = "Make Supplemental Policy", ValueFromPipelineByPropertyName = $true)][System.String]$SuppPolicyName,
        
        [ValidatePattern('\.xml$')]
        [ValidateScript({ Test-Path $_ -PathType 'Leaf' }, ErrorMessage = "The path you selected is not a file path.")]
        [parameter(Mandatory = $true, ParameterSetName = "Make Supplemental Policy", ValueFromPipelineByPropertyName = $true)]
        [System.String]$PolicyPath,
          
        [ValidateSet("Allow Microsoft Base", "Default Windows Base")]
        [Parameter(Mandatory = $true, ParameterSetName = "Make Policy From Audit Logs")][System.String]$BasePolicyType,

        [Parameter(Mandatory = $false, ParameterSetName = "Make AllowMSFT With Block Rules")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Light Policy")]        
        [parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make DefaultWindows With Block Rules")]
        [Switch]$Deployit,

        [Parameter(Mandatory = $false, ParameterSetName = "Make Light Policy")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make AllowMSFT With Block Rules")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make DefaultWindows With Block Rules")]
        [Switch]$TestMode,
        
        [Parameter(Mandatory = $false, ParameterSetName = "Make AllowMSFT With Block Rules")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Light Policy")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make DefaultWindows With Block Rules")]
        [Switch]$RequireEVSigners,

        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")][Switch]$Debugmode,

        [Parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [Switch]$AllowFileNameFallbacks,
        
        [ValidateSet("OriginalFileName", "InternalName", "FileDescription", "ProductName", "PackageFamilyName", "FilePath")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [System.String]$SpecificFileNameLevel,

        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")][Switch]$NoDeletedFiles,

        [Parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [Switch]$NoUserPEs,

        [Parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [Switch]$NoScript,

        [ValidateSet([Levelz])]
        [parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")]
        [System.String]$Levels,

        [ValidateSet([Fallbackz])]
        [parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]
        [parameter(Mandatory = $false, ParameterSetName = "Make Supplemental Policy")]
        [System.String[]]$Fallbacks,

        # Setting the maxim range to the maximum allowed log size by Windows Event viewer
        [ValidateRange(1024KB, 18014398509481983KB)]
        [Parameter(Mandatory = $false, ParameterSetName = "Prep MSFT Only Audit")]
        [Parameter(Mandatory = $false, ParameterSetName = "Prep Default Windows Audit")]
        [Parameter(Mandatory = $false, ParameterSetName = "Make Policy From Audit Logs")]        
        [System.Int64]$LogSize,
        
        [Parameter(Mandatory = $false)][Switch]$SkipVersionCheck    
    )

    begin {
        # Importing resources such as functions by dot-sourcing so that they will run in the same scope and their variables will be usable
        . "$psscriptroot\Resources.ps1"

        # argument tab auto-completion and ValidateSet for Fallbacks
        Class Fallbackz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Fallbackz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
   
                return [System.String[]]$Fallbackz
            }
        }

        # argument tab auto-completion and ValidateSet for levels
        Class Levelz : System.Management.Automation.IValidateSetValuesGenerator {
            [System.String[]] GetValidValues() {
                $Levelz = ('Hash', 'FileName', 'SignedVersion', 'Publisher', 'FilePublisher', 'LeafCertificate', 'PcaCertificate', 'RootCertificate', 'WHQL', 'WHQLPublisher', 'WHQLFilePublisher', 'PFN', 'FilePath', 'None')
       
                return [System.String[]]$Levelz
            }
        }
        
        $GetBlockRulesSCRIPTBLOCK = {             
            $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-block-rules.md"
            $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)" | Out-Null
            $Rules = $Matches[0]
            
            $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_1"\sFriendlyName="Allow\sKernel\sDrivers"\sFileName="\*".*/>', ''
            $Rules = $Rules -replace '<Allow\sID="ID_ALLOW_A_2"\sFriendlyName="Allow\sUser\smode\scomponents"\sFileName="\*".*/>', ''
            $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_1".*/>', ''
            $Rules = $Rules -replace '<FileRuleRef\sRuleID="ID_ALLOW_A_2".*/>', ''
            
            $Rules | Out-File 'Microsoft recommended block rules TEMP.xml'
            # Remove empty lines from the policy file
            Get-Content 'Microsoft recommended block rules TEMP.xml' | Where-Object { $_.trim() -ne "" } | Out-File 'Microsoft recommended block rules.xml'                
            Remove-Item 'Microsoft recommended block rules TEMP.xml' -Force
            Set-RuleOption -FilePath 'Microsoft recommended block rules.xml' -Option 3 -Delete
            Set-HVCIOptions -Strict -FilePath 'Microsoft recommended block rules.xml'
            [PSCustomObject]@{
                PolicyFile = 'Microsoft recommended block rules.xml'
            }
        }
           
        $GetDriverBlockRulesSCRIPTBLOCK = {       
            $MicrosoftRecommendeDriverBlockRules = Invoke-WebRequest -Uri "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules.md"
   
            $MicrosoftRecommendeDriverBlockRules -match "(?s)(?<=``````xml).*(?=``````)" | Out-Null
            $DriverRules = $Matches[0]

            $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_1"\sFriendlyName=""\sFileName="\*".*/>', ''
            $DriverRules = $DriverRules -replace '<Allow\sID="ID_ALLOW_ALL_2"\sFriendlyName=""\sFileName="\*".*/>', ''
            $DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_1".*/>', ''

            # not using this one because then during the merge there will be error - The reason is that "<FileRuleRef RuleID="ID_ALLOW_ALL_2" />" is the only FileruleRef in the xml and after removing it, the <SigningScenario> element will be empty
            #$DriverRules = $DriverRules -replace '<FileRuleRef\sRuleID="ID_ALLOW_ALL_2".*/>',''
            $DriverRules = $DriverRules -replace '<SigningScenario\sValue="12"\sID="ID_SIGNINGSCENARIO_WINDOWS"\sFriendlyName="Auto\sgenerated\spolicy[\S\s]*<\/SigningScenario>', ''

            $DriverRules | Out-File 'Microsoft recommended driver block rules TEMP.xml'
            # Remove empty lines from the policy file
            Get-Content 'Microsoft recommended driver block rules TEMP.xml' | Where-Object { $_.trim() -ne "" } | Out-File 'Microsoft recommended driver block rules.xml'
            Remove-Item 'Microsoft recommended driver block rules TEMP.xml' -Force
            Set-RuleOption -FilePath 'Microsoft recommended driver block rules.xml' -Option 3 -Delete
            Set-HVCIOptions -Strict -FilePath 'Microsoft recommended driver block rules.xml'
    
            Invoke-Command -ScriptBlock $DriversBlockListInfoGatheringSCRIPTBLOCK

            [PSCustomObject]@{
                PolicyFile = "Microsoft recommended driver block rules.xml"
            }        
        }

        $MakeAllowMSFTWithBlockRulesSCRIPTBLOCK = {
            param([System.Boolean]$NoCIP)
            # Get the latest Microsoft recommended block rules
            Invoke-Command -ScriptBlock $GetBlockRulesSCRIPTBLOCK | Out-Null                        
            Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml" -Destination "AllowMicrosoft.xml"
            Merge-CIPolicy -PolicyPaths .\AllowMicrosoft.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\AllowMicrosoftPlusBlockRules.xml | Out-Null     
            $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoftPlusBlockRules.xml -PolicyName "AllowMicrosoftPlusBlockRules Made On $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            $PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath .\AllowMicrosoftPlusBlockRules.xml -Version "1.0.0.0"
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ }
            @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\AllowMicrosoftPlusBlockRules.xml -Option $_ -Delete }        
            if ($TestMode -and $MakeAllowMSFTWithBlockRules) {
                & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting .\AllowMicrosoftPlusBlockRules.xml
            }
            if ($RequireEVSigners -and $MakeAllowMSFTWithBlockRules) {
                & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners .\AllowMicrosoftPlusBlockRules.xml
            }        
            Set-HVCIOptions -Strict -FilePath .\AllowMicrosoftPlusBlockRules.xml
            ConvertFrom-CIPolicy .\AllowMicrosoftPlusBlockRules.xml "$PolicyID.cip" | Out-Null   
            # Remove the extra files that were created during module operation and are no longer needed
            Remove-Item .\AllowMicrosoft.xml -Force
            Remove-Item 'Microsoft recommended block rules.xml' -Force

            [PSCustomObject]@{
                PolicyFile = "AllowMicrosoftPlusBlockRules.xml"
                BinaryFile = "$PolicyID.cip"
            }

            if ($Deployit -and $MakeAllowMSFTWithBlockRules) {            
                CiTool --update-policy "$PolicyID.cip" -json
                Write-host "`n"
            }
            if ($NoCIP)
            { Remove-Item -Path "$PolicyID.cip" -Force }
        }
        
        $MakeDefaultWindowsWithBlockRulesSCRIPTBLOCK = {
            param([System.Boolean]$NoCIP)
            Invoke-Command -ScriptBlock $GetBlockRulesSCRIPTBLOCK | Out-Null                        
            Copy-item -Path "C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Enforced.xml" -Destination "DefaultWindows_Enforced.xml"
            # Scan PowerShell core directory and allow its files in the Default Windows base policy so that module can still be used once it's been deployed
            if (Test-Path "C:\Program Files\PowerShell") {
                Write-Host "Creating allow rules for PowerShell in the DefaultWindows base policy so you can continue using this module after deploying it." -ForegroundColor Blue                    
                New-CIPolicy -ScanPath "C:\Program Files\PowerShell" -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml
                Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, .\AllowPowerShell.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null
            }
            else {
                Merge-CIPolicy -PolicyPaths .\DefaultWindows_Enforced.xml, 'Microsoft recommended block rules.xml' -OutputFilePath .\DefaultWindowsPlusBlockRules.xml | Out-Null                         
            }                  
            
            $PolicyID = Set-CIPolicyIdInfo -FilePath .\DefaultWindowsPlusBlockRules.xml -PolicyName "DefaultWindowsPlusBlockRules Made On $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID
            $PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyVersion -FilePath .\DefaultWindowsPlusBlockRules.xml -Version "1.0.0.0"
            @(0, 2, 5, 6, 11, 12, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ }
            @(3, 4, 9, 10, 13, 18) | ForEach-Object { Set-RuleOption -FilePath .\DefaultWindowsPlusBlockRules.xml -Option $_ -Delete }        
            if ($TestMode -and $MakeDefaultWindowsWithBlockRules) {
                & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting .\DefaultWindowsPlusBlockRules.xml
            }
            if ($RequireEVSigners -and $MakeDefaultWindowsWithBlockRules) {
                & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners .\DefaultWindowsPlusBlockRules.xml
            }        
            Set-HVCIOptions -Strict -FilePath .\DefaultWindowsPlusBlockRules.xml
            ConvertFrom-CIPolicy .\DefaultWindowsPlusBlockRules.xml "$PolicyID.cip" | Out-Null   

            Remove-item .\AllowPowerShell.xml -Force -ErrorAction SilentlyContinue
            Remove-Item .\DefaultWindows_Enforced.xml -Force
            Remove-Item 'Microsoft recommended block rules.xml' -Force

            [PSCustomObject]@{
                PolicyFile = "DefaultWindowsPlusBlockRules.xml"
                BinaryFile = "$PolicyID.cip"
            }

            if ($Deployit -and $MakeDefaultWindowsWithBlockRules) {            
                CiTool --update-policy "$PolicyID.cip" -json
                Write-host "`n"
            }
            if ($NoCIP)
            { Remove-Item -Path "$PolicyID.cip" -Force }
            
        }

        $DeployLatestDriverBlockRulesSCRIPTBLOCK = {        
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

        $SetAutoUpdateDriverBlockRulesSCRIPTBLOCK = {
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

        $PrepMSFTOnlyAuditSCRIPTBLOCK = {
            if ($PrepMSFTOnlyAudit -and $LogSize) { . Set-LogSize -LogSize $LogSize }
            Copy-item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\AllowMicrosoft.xml -Destination .\AllowMicrosoft.xml
            Set-RuleOption -FilePath .\AllowMicrosoft.xml -Option 3
            $PolicyID = Set-CIPolicyIdInfo -FilePath .\AllowMicrosoft.xml -ResetPolicyID
            $PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyIdInfo -PolicyName "PrepMSFTOnlyAudit" -FilePath .\AllowMicrosoft.xml
            ConvertFrom-CIPolicy .\AllowMicrosoft.xml "$PolicyID.cip" | Out-Null
            CiTool --update-policy "$PolicyID.cip" -json
            Remove-Item "AllowMicrosoft.xml" -Force
            Remove-Item "$PolicyID.cip" -Force
            Write-host "`nThe default AllowMicrosoft policy has been deployed in Audit mode. No reboot required." -ForegroundColor Magenta     
        }

        $PrepDefaultWindowsAuditSCRIPTBLOCK = {
            if ($PrepDefaultWindowsAudit -and $LogSize) { . Set-LogSize -LogSize $LogSize }
            Copy-item -Path C:\Windows\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml -Destination .\DefaultWindows_Audit.xml
           
            # Making Sure neither PowerShell core nor WDACConfig module files are added to the Supplemental policy created by -MakePolicyFromAuditLogs parameter
            # by addibg them first to the deployed Default Windows policy in Audit mode. Because WDACConfig module files don't need to be allowed to run and
            # PowerShell core files will be added to the DefaultWindows Base policy anyway
            if (Test-Path "C:\Program Files\PowerShell") {               
                New-CIPolicy -ScanPath "C:\Program Files\PowerShell" -Level FilePublisher -NoScript -Fallback Hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\AllowPowerShell.xml
                New-CIPolicy -ScanPath "$psscriptroot" -Level hash -UserPEs -UserWriteablePaths -MultiplePolicyFormat -FilePath .\WDACConfigModule.xml
                Merge-CIPolicy -PolicyPaths .\DefaultWindows_Audit.xml, .\AllowPowerShell.xml, .\WDACConfigModule.xml -OutputFilePath .\DefaultWindows_Audit_temp.xml | Out-Null
            } 

            Remove-Item DefaultWindows_Audit.xml -Force            
            Rename-Item -Path .\DefaultWindows_Audit_temp.xml -NewName "DefaultWindows_Audit.xml" -Force

            Remove-Item WDACConfigModule.xml -Force
            Remove-Item AllowPowerShell.xml -Force
                   
            Set-RuleOption -FilePath .\DefaultWindows_Audit.xml -Option 3
            $PolicyID = Set-CIPolicyIdInfo -FilePath .\DefaultWindows_Audit.xml -ResetPolicyID
            $PolicyID = $PolicyID.Substring(11)
            Set-CIPolicyIdInfo -PolicyName "PrepDefaultWindows" -FilePath .\DefaultWindows_Audit.xml
            ConvertFrom-CIPolicy .\DefaultWindows_Audit.xml "$PolicyID.cip" | Out-Null
            CiTool --update-policy "$PolicyID.cip" -json
            Remove-Item "DefaultWindows_Audit.xml" -Force
            Remove-Item "$PolicyID.cip" -Force
            Write-host "`nThe defaultWindows policy has been deployed in Audit mode. No reboot required." -ForegroundColor Magenta    
        }

        $MakePolicyFromAuditLogsSCRIPTBLOCK = {
            if ($MakePolicyFromAuditLogs -and $LogSize) { . Set-LogSize -LogSize $LogSize }
            # Make sure there is no leftover files from previous operations of this same command
            Remove-Item -Path "$home\WDAC\*" -Recurse -Force -ErrorAction SilentlyContinue
            # Create a working directory in user's folder
            New-item -Type Directory -Path "$home\WDAC" -Force | Out-Null
            Set-Location "$home\WDAC"

            ############################### Base Policy Processing ###############################

            switch ($BasePolicyType) {

                "Allow Microsoft Base" {
                    Invoke-Command -ScriptBlock $MakeAllowMSFTWithBlockRulesSCRIPTBLOCK | Out-Null
                    $xml = [xml](Get-Content .\AllowMicrosoftPlusBlockRules.xml)
                    $BasePolicyID = $xml.SiPolicy.PolicyID
                    # define the location of the base policy
                    $BasePolicy = "AllowMicrosoftPlusBlockRules.xml" 
                }
                "Default Windows Base" {
                    Invoke-Command -ScriptBlock $MakeDefaultWindowsWithBlockRulesSCRIPTBLOCK | Out-Null
                    $xml = [xml](Get-Content .\DefaultWindowsPlusBlockRules.xml)
                    $BasePolicyID = $xml.SiPolicy.PolicyID
                    # define the location of the base policy
                    $BasePolicy = "DefaultWindowsPlusBlockRules.xml" 
                }
            }          
  
            if ($TestMode -and $MakePolicyFromAuditLogs) {
                & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting $BasePolicy
            }
            if ($RequireEVSigners -and $MakePolicyFromAuditLogs) {
                & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners $BasePolicy
            }

            ############################### Supplemental Processing ###############################

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
  
            # Produce a policy xml file from event viewer logs
            Write-host "Scanning Windows Event logs and creating a policy file, please wait..." -ForegroundColor Cyan
              
            <#  keeping this for historic purposes
            # Create an array to dynamically feed parameters to New-CIPolicy Cmdlet
            $PolicyMakerArray = @()
            $PolicyMakerArray += 'New-CIPolicy -FilePath "AuditLogsPolicy_NoDeletedFiles.xml"'
            $PolicyMakerArray += "-Audit -Level $AssignedLevels -Fallback $AssignedFallbacks"
            if ($AllowFileNameFallbacks) { $PolicyMakerArray += "-AllowFileNameFallbacks" }
            if ($SpecificFileNameLevel) { $PolicyMakerArray += "-SpecificFileNameLevel $SpecificFileNameLevel" }
            if ($NoScript) { $PolicyMakerArray += "-NoScript" }
            if (!$NoUserPEs) { $PolicyMakerArray += "-UserPEs" }            
            $PolicyMakerArray += "-MultiplePolicyFormat -UserWriteablePaths -WarningAction SilentlyContinue"            
            
            $PolicyMakerArray = $PolicyMakerArray -Join " " 
            write-host "The following command is running: `n$PolicyMakerArray" -ForegroundColor Magenta
            $PolicyMakerArray | Invoke-Expression
            #>

            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                FilePath             = "AuditLogsPolicy_NoDeletedFiles.xml"
                Audit                = $true
                Level                = $AssignedLevels
                Fallback             = $AssignedFallbacks
                MultiplePolicyFormat = $true
                UserWriteablePaths   = $true
                WarningAction        = 'SilentlyContinue'
            }
            # Assess user input parameters and add the required parameters to the hash table
            if ($AllowFileNameFallbacks) { $PolicyMakerHashTable['AllowFileNameFallbacks'] = $true }
            if ($SpecificFileNameLevel) { $PolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }    
            if ($NoScript) { $PolicyMakerHashTable['NoScript'] = $true }        
            if (!$NoUserPEs) { $PolicyMakerHashTable['UserPEs'] = $true } 

            write-host "Generating Supplemental policy with the following specifications:" -ForegroundColor Magenta
            $PolicyMakerHashTable
            Write-Host "`n"
            # Create the supplemental policy via parameter splatting
            New-CIPolicy @PolicyMakerHashTable
            
            # Calling the script block from Resources file that is dot-sourced
            $DirveLettersGlobalRootFix = Invoke-Command -ScriptBlock $DirveLettersGlobalRootFixScriptBlock       

            # Get Event viewer logs for code integrity - check the file path of all of the files in the log, resolve them using the command above - show files that are no longer available on the disk
            $AuditEventLogsDeletedFilesScriptBlock = {
                foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 }) {
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
                        }
                        if (-NOT (Test-Path $_.'File Name')) {
                            $_ | Select-Object FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                        }
                    }
                }
            }
            # storing the output from the scriptblock above in a variable
            $DeletedFileHashesArray = Invoke-Command -ScriptBlock $AuditEventLogsDeletedFilesScriptBlock

            # run the following only if there are any event logs for files no longer on the disk and if -NoDeletedFiles switch parameter wasn't used
            if ($DeletedFileHashesArray -and !$NoDeletedFiles) {

                # Create File Rules based on hash of the files no longer available on the disk and store them in the $Rules variable
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
                Merge-CIPolicy -PolicyPaths "AuditLogsPolicy_NoDeletedFiles.xml", .\DeletedFilesHashes.xml -OutputFilePath .\SupplementalPolicy.xml | Out-Null
            }
            # do this only if there are no event logs detected with files no longer on the disk, so we use the policy file created earlier using Audit even logs
            else {
                Rename-Item "AuditLogsPolicy_NoDeletedFiles.xml" -NewName "SupplementalPolicy.xml" -Force
            }      
            # Convert the SupplementalPolicy.xml policy file from base policy to supplemental policy of our base policy
            Set-CIPolicyVersion -FilePath "SupplementalPolicy.xml" -Version "1.0.0.0"
            $PolicyID = Set-CIPolicyIdInfo -FilePath "SupplementalPolicy.xml" -PolicyName "Supplemental Policy made from Audit Event Logs on $(Get-Date -Format 'MM-dd-yyyy')" -ResetPolicyID -BasePolicyToSupplementPath $BasePolicy
            $PolicyID = $PolicyID.Substring(11)        
            # Make sure policy rule options that don't belong to a Supplemental policy don't exit
            @(0, 1, 2, 3, 4, 8, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object { Set-RuleOption -FilePath "SupplementalPolicy.xml" -Option $_ -Delete }

            # Set the hypervisor Code Integrity option for Supplemental policy to Strict        
            Set-HVCIOptions -Strict -FilePath "SupplementalPolicy.xml"
            # convert the Supplemental Policy file to .cip binary file
            ConvertFrom-CIPolicy "SupplementalPolicy.xml" "$policyID.cip" | Out-Null

            [PSCustomObject]@{
                BasePolicyFile = $BasePolicy    
                BasePolicyGUID = $BasePolicyID
            }
            [PSCustomObject]@{
                SupplementalPolicyFile = "SupplementalPolicy.xml"
                SupplementalPolicyGUID = $PolicyID
            }       

            if (-NOT $Debugmode) {
                Remove-Item -Path "AuditLogsPolicy_NoDeletedFiles.xml" -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "FileRulesAndFileRefs.txt" -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "DeletedFilesHashes.xml" -Force -ErrorAction SilentlyContinue
            }

            if ($Deployit -and $MakePolicyFromAuditLogs) {            
                CiTool --update-policy "$BasePolicyID.cip" -json
                CiTool --update-policy "$policyID.cip" -json
                Write-host "`nBase policy and Supplemental Policies deployed and activated.`n" -ForegroundColor Green
                
                # Get the correct Prep mode Audit policy ID to remove from the system
                switch ($BasePolicyType) {
                    "Allow Microsoft Base" {
                        $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq "PrepMSFTOnlyAudit" }).PolicyID
                    }
                    "Default Windows Base" {
                        $IDToRemove = ((CiTool -lp -json | ConvertFrom-Json).Policies | Where-Object { $_.FriendlyName -eq "PrepDefaultWindows" }).PolicyID
                    }
                }
                CiTool --remove-policy "{$IDToRemove}" -json
                Write-host "System restart required to finish removing the Audit mode Prep policy" -ForegroundColor Green                
            }     
        }

        $MakeLightPolicySCRIPTBLOCK = {
            # Delete the any policy with the same name in the current working directory
            Remove-Item -Path "SignedAndReputable.xml" -Force -ErrorAction SilentlyContinue
            Invoke-Command $MakeAllowMSFTWithBlockRulesSCRIPTBLOCK -ArgumentList $true | Out-Null
            Rename-Item -Path "AllowMicrosoftPlusBlockRules.xml" -NewName "SignedAndReputable.xml" -Force
            @(14, 15) | ForEach-Object { Set-RuleOption -FilePath .\SignedAndReputable.xml -Option $_ }
            if ($TestMode -and $MakeLightPolicy) {
                & $TestModeSCRIPTBLOCK -PolicyPathToEnableTesting .\SignedAndReputable.xml
            }
            if ($RequireEVSigners -and $MakeLightPolicy) {
                & $RequireEVSignersSCRIPTBLOCK -PolicyPathToEnableEVSigners .\SignedAndReputable.xml
            }
            $BasePolicyID = Set-CiPolicyIdInfo -FilePath .\SignedAndReputable.xml -ResetPolicyID -PolicyName "SignedAndReputable policy deployed on $(Get-Date -Format 'MM-dd-yyyy')"
            $BasePolicyID = $BasePolicyID.Substring(11)        
            Set-CIPolicyVersion -FilePath .\SignedAndReputable.xml -Version "1.0.0.0"
            Set-HVCIOptions -Strict -FilePath .\SignedAndReputable.xml        
            ConvertFrom-CIPolicy .\SignedAndReputable.xml "$BasePolicyID.cip" | Out-Null
            # Configure required services for ISG authorization
            Start-Process -FilePath 'C:\Windows\System32\appidtel.exe' -ArgumentList 'start' -Wait -NoNewWindow
            Start-Process -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'config', 'appidsvc', "start= auto" -Wait -NoNewWindow
            if ($Deployit -and $MakeLightPolicy) {
                CiTool --update-policy "$BasePolicyID.cip" -json
                Write-host -NoNewline "`nSignedAndReputable.xml policy has been deployed.`n" -ForegroundColor Green            
            }
            [PSCustomObject]@{
                BasePolicyFile = "SignedAndReputable.xml"      
                BasePolicyGUID = $BasePolicyID
            }       
        }

        $MakeSupplementalPolicySCRIPTBLOCK = {

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
            
            # Creating a hash table to dynamically add parameters based on user input and pass them to New-Cipolicy cmdlet
            [System.Collections.Hashtable]$PolicyMakerHashTable = @{
                FilePath             = "SupplementalPolicy$SuppPolicyName.xml"
                ScanPath             = $ScanLocation
                Level                = $AssignedLevels
                Fallback             = $AssignedFallbacks
                MultiplePolicyFormat = $true
                UserWriteablePaths   = $true
            }
            # Assess user input parameters and add the required parameters to the hash table
            if ($AllowFileNameFallbacks) { $PolicyMakerHashTable['AllowFileNameFallbacks'] = $true }
            if ($SpecificFileNameLevel) { $PolicyMakerHashTable['SpecificFileNameLevel'] = $SpecificFileNameLevel }  
            if ($NoScript) { $PolicyMakerHashTable['NoScript'] = $true }                 
            if (!$NoUserPEs) { $PolicyMakerHashTable['UserPEs'] = $true } 

            write-host "Generating Supplemental policy with the following specifications:" -ForegroundColor Magenta
            $PolicyMakerHashTable
            Write-Host "`n"
            # Create the supplemental policy via parameter splatting
            New-CIPolicy @PolicyMakerHashTable           
            
            $policyID = Set-CiPolicyIdInfo -FilePath "SupplementalPolicy$SuppPolicyName.xml" -ResetPolicyID -BasePolicyToSupplementPath $PolicyPath -PolicyName "$SuppPolicyName"
            $policyID = $policyID.Substring(11)
            Set-CIPolicyVersion -FilePath "SupplementalPolicy$SuppPolicyName.xml" -Version "1.0.0.0"
            # Make sure policy rule options that don't belong to a Supplemental policy don't exit             
            @(0, 1, 2, 3, 4, 9, 10, 11, 12, 15, 16, 17, 19, 20) | ForEach-Object {
                Set-RuleOption -FilePath "SupplementalPolicy$SuppPolicyName.xml" -Option $_ -Delete }        
            Set-HVCIOptions -Strict -FilePath "SupplementalPolicy$SuppPolicyName.xml"        
            ConvertFrom-CIPolicy "SupplementalPolicy$SuppPolicyName.xml" "$policyID.cip" | Out-Null
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
        # Script block that is used to add policy rule options 9 and 10 to the base policy
        $TestModeSCRIPTBLOCK = { 
            param([System.String]$PolicyPathToEnableTesting)
            @(9, 10) | ForEach-Object { Set-RuleOption -FilePath $PolicyPathToEnableTesting -Option $_ }
        }
        # Script block that is used to add Require EV Singers policy rule option to the base policy
        $RequireEVSignersSCRIPTBLOCK = {
            param([System.String]$PolicyPathToEnableEVSigners)
            Set-RuleOption -FilePath $PolicyPathToEnableEVSigners -Option 8
        }
        # Script block that is used to supply extra information regarding Microsoft recommended driver block rules in commands that use them
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
        # Stop operation as soon as there is an error, anywhere, unless explicitly specified otherwise
        $ErrorActionPreference = 'Stop'
        if (-NOT $SkipVersionCheck) { . Update-self }    
    }

    process {

        if ($GetBlockRules) { Invoke-Command -ScriptBlock $GetBlockRulesSCRIPTBLOCK }                                
        if ($GetDriverBlockRules) { Invoke-Command -ScriptBlock $GetDriverBlockRulesSCRIPTBLOCK }   
        if ($MakeAllowMSFTWithBlockRules) { Invoke-Command -ScriptBlock $MakeAllowMSFTWithBlockRulesSCRIPTBLOCK }
        if ($DeployLatestDriverBlockRules) { Invoke-Command -ScriptBlock $DeployLatestDriverBlockRulesSCRIPTBLOCK }                               
        if ($SetAutoUpdateDriverBlockRules) { Invoke-Command -ScriptBlock $SetAutoUpdateDriverBlockRulesSCRIPTBLOCK }                                
        if ($MakePolicyFromAuditLogs) { Invoke-Command -ScriptBlock $MakePolicyFromAuditLogsSCRIPTBLOCK }                                
        if ($PrepMSFTOnlyAudit) { Invoke-Command -ScriptBlock $PrepMSFTOnlyAuditSCRIPTBLOCK }        
        if ($MakeLightPolicy) { Invoke-Command -ScriptBlock $MakeLightPolicySCRIPTBLOCK }
        if ($MakeSupplementalPolicy) { Invoke-Command -ScriptBlock $MakeSupplementalPolicySCRIPTBLOCK }
        if ($MakeDefaultWindowsWithBlockRules) { Invoke-Command -ScriptBlock $MakeDefaultWindowsWithBlockRulesSCRIPTBLOCK }
        if ($PrepDefaultWindowsAudit) { Invoke-Command -ScriptBlock $PrepDefaultWindowsAuditSCRIPTBLOCK }

    }    
  
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

.PARAMETER GetBlockRules
Create Microsoft recommended block rules xml policy and remove the allow rules

.PARAMETER GetDriverBlockRules
Create Microsoft recommended driver block rules xml policy and remove the allow rules

.PARAMETER MakeAllowMSFTWithBlockRules
Make WDAC policy by merging AllowMicrosoft policy with the recommended block rules

.PARAMETER DeployLatestDriverBlockRules
Automatically download and deploy the latest Microsoft Recommended Driver Block Rules from Microsoft's source

.PARAMETER SetAutoUpdateDriverBlockRules
Make a Scheduled Task that automatically runs every 7 days to download the newest Microsoft Recommended driver block rules

.PARAMETER PrepMSFTOnlyAudit
Prepare the system for Audit mode using AllowMicrosoft default policy

.PARAMETER MakePolicyFromAuditLogs
Make WDAC Policy from Audit event logs that also covers files no longer on disk

.PARAMETER MakeLightPolicy
Make WDAC Policy with ISG for Lightly Managed system

.PARAMETER MakeSupplementalPolicy 
Make a Supplemental policy by scanning a directory    

.PARAMETER MakeDefaultWindowsWithBlockRules
Make WDAC policy by merging DefaultWindows policy with the recommended block rules

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
