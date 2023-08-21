# Stop the execution when there is an error
$ErrorActionPreference = 'Stop'

# Change the execution policy temporarily only for the current PowerShell session
Set-ExecutionPolicy Bypass -Scope Process

# Custom colors
[scriptblock]$WriteFuchsia = { Write-Host "$($PSStyle.Foreground.FromRGB(236,68,155))$($args[0])$($PSStyle.Reset)" }
[scriptblock]$WriteOrange = { Write-Host "$($PSStyle.Foreground.FromRGB(255,165,0))$($args[0])$($PSStyle.Reset)" }
[scriptblock]$WriteMintGreen = { Write-Host "$($PSStyle.Foreground.FromRGB(152,255,152))$($args[0])$($PSStyle.Reset)" }

&$WriteOrange "`r`n"
&$WriteOrange "################################################################################################`r`n"
&$WriteMintGreen "##  This will remove all of the hardening measures applied by Harden Windows Security Script  ##`r`n"
&$WriteOrange "################################################################################################`r`n"

# Give user a chance to exit if they accidentally ran this
Pause

Write-Progress -Activity 'Backing up Controlled Folder Access exclusion list' -Status 'Processing' -PercentComplete 10

# backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
# doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
# no user customization will be affected
[string[]]$CFAAllowedAppsBackup = (Get-MpPreference).ControlledFolderAccessAllowedApplications

# Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
# so that the script can run without interruption. This change is reverted at the end.
Get-ChildItem -Path "$PSHOME\*.exe" | ForEach-Object {
    Add-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName
}

# doing a try-finally block on the entire script so that when CTRL + C is pressed to forcefully exit the script,
# or break is passed, clean up will still happen for secure exit
try {
   
    #region RequirementsCheck

    # check if user's OS is Windows Home edition
    if ((Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU -eq '101') {
        Write-Error 'Windows Home edition detected, exiting...'
        break
    }

    # check if user's OS is latest version
    if (-NOT ([System.Environment]::OSVersion.Version -ge [version]'10.0.22621')) {
        Write-Error "You're not using the latest version of the Windows OS, exiting..."
        break
    }

    # check to make sure TPM is available and enabled
    [bool]$TPMFlag1 = (Get-Tpm).tpmpresent
    [bool]$TPMFlag2 = (Get-Tpm).tpmenabled
    if (!$TPMFlag1 -or !$TPMFlag2) {
        Write-Error 'TPM is not available or enabled, please go to your UEFI settings and enable it and then run the script again.'
        break    
    }    
   
     
    # create our working directory
    New-Item -ItemType Directory -Path "$env:TEMP\HardeningXStuff\" -Force | Out-Null

    # working directory assignment
    [string]$WorkingDir = "$env:TEMP\HardeningXStuff\"

    # change location to the new directory
    Set-Location -Path $WorkingDir

    # Clean up script block
    [scriptblock]$CleanUp = { Set-Location $HOME; Remove-Item -Recurse "$env:TEMP\HardeningXStuff\" -Force; exit }

    Write-Progress -Activity 'Downloading the required files' -Status 'Processing' -PercentComplete 30

    # Hiding Invoke-WebRequest progress because it creates lingering visual effect on PowerShell console for some reason
    # https://github.com/PowerShell/PowerShell/issues/14348

    # https://stackoverflow.com/questions/18770723/hide-progress-of-Invoke-WebRequest
    # Create an in-memory module so $ScriptBlock doesn't run in new scope
    $null = New-Module {
        function Invoke-WithoutProgress {
            [CmdletBinding()]
            param (
                [Parameter(Mandatory)][scriptblock]$ScriptBlock
            )
            # Save current progress preference and hide the progress
            $prevProgressPreference = $global:ProgressPreference
            $global:ProgressPreference = 'SilentlyContinue'
            try {
                # Run the script block in the scope of the caller of this module function
                . $ScriptBlock
            }
            finally {
                # Restore the original behavior
                $global:ProgressPreference = $prevProgressPreference
            }
        }
    }
    
    try {                
        Invoke-WithoutProgress {                   
            # Download Registry CSV file from GitHub or Azure DevOps
            try {
                Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/Registry.csv' -OutFile '.\Registry.csv' -ErrorAction Stop                
            }
            catch {
                Write-Host 'Using Azure DevOps...' -ForegroundColor Yellow
                Invoke-WebRequest -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Registry.csv' -OutFile '.\Registry.csv' -ErrorAction Stop
            }

            # Download Process Mitigations CSV file from GitHub or Azure DevOps
            try {
                Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Payload/ProcessMitigations.csv' -OutFile '.\ProcessMitigations.csv' -ErrorAction Stop                
            }
            catch {
                Write-Host 'Using Azure DevOps...' -ForegroundColor Yellow
                Invoke-WebRequest -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/ProcessMitigations.csv' -OutFile '.\ProcessMitigations.csv' -ErrorAction Stop
            }
        }
    }
    catch {
        Write-Error "The required files couldn't be downloaded, Make sure you have Internet connection."
        &$CleanUp   
    }

    Write-Progress -Activity 'Deleting all group policies' -Status 'Processing' -PercentComplete 45

    if (Test-Path -Path 'C:\Windows\System32\GroupPolicy') {
        Remove-Item -Path 'C:\Windows\System32\GroupPolicy' -Recurse -Force
    }

    Write-Progress -Activity 'Deleting all registry keys created by the hardening script' -Status 'Processing' -PercentComplete 60
     
    [System.Object[]]$Items = Import-Csv '.\Registry.csv' -Delimiter ','
    foreach ($Item in $Items) { 
        if (Test-Path -Path $item.path) {       
            Remove-ItemProperty -Path $Item.path -Name $Item.key -Force -ErrorAction SilentlyContinue 
        }    
    } 

    # To completely remove the Edge policy since only its sub-keys are removed by the command above
    Remove-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList' -Force -Recurse -ErrorAction SilentlyContinue
    
    # Restore Security group policies back to their default states

    Write-Progress -Activity 'Restoring the default Security group policies' -Status 'Processing' -PercentComplete 70
   
    Invoke-WithoutProgress {
        # Download LGPO program from Microsoft servers
        Invoke-WebRequest -Uri 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip' -OutFile '.\LGPO.zip' -ErrorAction Stop
        # Download the default security group policy inf from GitHub repository
        Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Resources/Default%20Security%20Policy.inf' -OutFile '.\Default Security Policy.inf' -ErrorAction Stop
    }

    # unzip the LGPO file
    Expand-Archive -Path .\LGPO.zip -DestinationPath .\ -Force  
    .\'LGPO_30\LGPO.exe' /s '.\Default Security Policy.inf'

    # Remove-Item -Path -Force

    # Enable LMHOSTS lookup protocol on all network adapters again
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'EnableLMHOSTS' -Value '1' -Type DWord

    # Disable restart notification for Windows update
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'RestartNotificationsAllowed2' -Value '0' -Type DWord

    # Re-enables the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines
    SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable | Out-Null

    Write-Progress -Activity 'Restoring Microsoft Defender configurations back to their default states' -Status 'Processing' -PercentComplete 80
   
    # Disable the advanced new security features of the Microsoft Defender
    Set-MpPreference -AllowSwitchToAsyncInspection $False
    Set-MpPreference -OobeEnableRtpAndSigUpdate $False
    Set-MpPreference -IntelTDTEnabled $False
    Set-MpPreference -DisableRestorePoint $True
    Set-MpPreference -PerformanceModeStatus Enabled
    Set-MpPreference -EnableConvertWarnToBlock $False   
    # Set Microsoft Defender engine and platform update channels to NotConfigured State           
    Set-MpPreference -EngineUpdatesChannel NotConfigured
    Set-MpPreference -PlatformUpdatesChannel NotConfigured

    # Disable Mandatory ASLR
    Set-ProcessMitigation -System -Disable ForceRelocateImages
    
    # Remove Process Mitigations

    [System.Object[]]$ProcessMitigations = Import-Csv '.\ProcessMitigations.csv' -Delimiter ','
    # Group the data by ProgramName
    [System.Object[]]$GroupedMitigations = $ProcessMitigations | Group-Object ProgramName
    [System.Object[]]$AllAvailableMitigations = (Get-ItemProperty -Path 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')
    
    Write-Progress -Activity 'Removing Process Mitigations for apps' -Status 'Processing' -PercentComplete 90
   
    # Loop through each group
    foreach ($Group in $GroupedMitigations) {    
        # To separate the filename from full path of the item in the CSV and then check whether it exists in the system registry
        if ($Group.Name -match '\\([^\\]+)$') {
            if ($Matches[1] -in $AllAvailableMitigations.pschildname) {
                Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Matches[1])" -Recurse -Force
            }        
        }
        elseif ($Group.Name -in $AllAvailableMitigations.pschildname) {
            Remove-Item -Path "Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Group.Name)" -Recurse -Force
        }
    } 
    
    # Set Data Execution Prevention (DEP) back to its default value
    bcdedit.exe /set '{current}' nx OptIn | Out-Null
         
    # Remove the scheduled task that keeps the Microsoft recommended driver block rules updated

    # Define the name and path of the task
    [string]$taskName = 'MSFT Driver Block list update'
    [string]$taskPath = '\MSFT Driver Block list update\'

    if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false | Out-Null
    }       

    # Enables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles
    Get-NetFirewallRule |
    Where-Object { $_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302' -and $_.Direction -eq 'inbound' } |
    ForEach-Object { Enable-NetFirewallRule -DisplayName $_.DisplayName }
    
    # Disable SMB Encryption - using force to confirm the action
    Set-SmbServerConfiguration -EncryptData $False -Force                    
          
    # Remove any custom views added by this script for Event Viewer
    if (Test-Path -Path 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script') {
        Remove-Item -Path 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script' -Recurse -Force
    }

    Write-Progress -Activity 'Complete' -Status 'Complete' -PercentComplete 100   
}
finally {

    # Reverting the PowerShell executables allow listings in Controlled folder access
    Get-ChildItem -Path "$PSHOME\*.exe" | ForEach-Object {
        Remove-MpPreference -ControlledFolderAccessAllowedApplications $_.FullName
    }
    # restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
    # they will be restored as well, so user customization will remain intact
    if ($null -ne $CFAAllowedAppsBackup) { 
        $CFAAllowedAppsBackup | ForEach-Object {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $_
        }
    }
    
    Set-Location $HOME; Remove-Item -Recurse "$env:TEMP\HardeningXStuff\" -Force -ErrorAction SilentlyContinue    
}

&$WriteFuchsia 'Operation Completed, please restart your computer.'
