Function Unprotect-WindowsSecurity {
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'All'
    )]
    [OutputType([System.String])]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyProcessMitigations')]
        [System.Management.Automation.SwitchParameter]$OnlyProcessMitigations,

        [ValidateSet('Downloads-Defense-Measures', 'Dangerous-Script-Hosts-Blocking')]
        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyWDACPolicies')]
        [System.String[]]$WDACPoliciesToRemove,

        [Parameter(Mandatory = $false, ParameterSetName = 'OnlyCountryIPBlockingFirewallRules')]
        [System.Management.Automation.SwitchParameter]$OnlyCountryIPBlockingFirewallRules,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.SwitchParameter]$Force
    )

    begin {
        [HardeningModule.Initializer]::Initialize()

        Write-Verbose -Message 'Importing the required sub-modules'
        Import-Module -FullyQualifiedName "$([HardeningModule.GlobalVars]::Path)\Shared\Update-self.psm1" -Force -Verbose:$false

        # Makes sure this cmdlet is invoked with Admin privileges
        if (-NOT ([HardeningModule.UserPrivCheck]::IsAdmin())) {
            Throw [System.Security.AccessControl.PrivilegeNotHeldException] 'Administrator'
        }

        Write-Verbose -Message 'Checking for updates...'
        Update-Self -InvocationStatement $MyInvocation.Statement

        # The total number of the steps for the parent/main progress bar to render
        [System.Int16]$TotalMainSteps = 7
        [System.Int16]$CurrentMainStep = 0

        # do not prompt for confirmation if the -Force switch is used
        # if both -Force and -Confirm switches are used, the prompt for confirmation will still be correctly shown
        if ($Force -and -Not $Confirm) {
            $ConfirmPreference = 'None'
        }

        #Region Helper-Functions
        Function Remove-WDACPolicies {
            param([System.String[]]$PolicyNames)
            <#
            .SYNOPSIS
                Helper function to remove the Downloads Defense Measures WDAC policy
            .INPUTS
                None
            .OUTPUTS
                System.Void
            #>

            Write-Verbose -Message 'Getting the currently deployed base policies'
            [System.String[]]$ToRemove = foreach ($Name in ((&"$env:SystemDrive\Windows\System32\CiTool.exe" -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) -and ($_.IsOnDisk -eq 'True') }).FriendlyName) {
                if ($Name -in $PolicyNames) {
                    $Name
                }
            }

            if ($ToRemove.Count -gt 0) {

                if (-NOT (Get-InstalledModule -Name 'WDACConfig' -ErrorAction SilentlyContinue -Verbose:$false)) {
                    Write-Verbose -Message 'Installing WDACConfig module because it is not installed'
                    Install-Module -Name 'WDACConfig' -Force -Verbose:$false
                }
                Write-Verbose -Message "Removing the WDAC policies: $($ToRemove -join ', ')"
                Remove-WDACConfig -UnsignedOrSupplemental -PolicyNames $ToRemove -SkipVersionCheck
            }
            else {
                Write-Verbose -Message "$($PolicyNames -join ', ') is/are either not deployed or already removed"
            }
        }
        Function Remove-ProcessMitigations {
            <#
            .SYNOPSIS
                A helper function to only remove the Process Mitigations / Exploit Protection settings
            .INPUTS
                None
            .OUTPUTS
                System.Void
            #>

            Write-Verbose -Message 'Removing the Process Mitigations / Exploit Protection settings'

            # Disable Mandatory ASLR
            Set-ProcessMitigation -System -Disable ForceRelocateImages

            # Only keep the mitigations that are allowed to be removed
            # It is important for any executable whose name is mentioned as a key in "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" Should have its RemovalAllowed property in the Process Mitigations CSV file set to False
            [HardeningModule.ProcessMitigationsParser+ProcessMitigationsRecords[]]$ProcessMitigations = [HardeningModule.GlobalVars]::ProcessMitigations | Where-Object -FilterScript { $_.RemovalAllowed -eq 'True' }

            # Group the data by ProgramName
            [Microsoft.PowerShell.Commands.GroupInfo[]]$GroupedMitigations = $ProcessMitigations | Group-Object -Property ProgramName
            [System.Object[]]$AllAvailableMitigations = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')

            # Loop through each group
            foreach ($Group in $GroupedMitigations) {
                # To separate the filename from full path of the item in the CSV and then check whether it exists in the system registry
                if ($Group.Name -match '\\([^\\]+)$') {
                    if ($Matches[1] -in $AllAvailableMitigations.pschildname) {
                        Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Matches[1])" -Recurse -Force
                    }
                }
                elseif ($Group.Name -in $AllAvailableMitigations.pschildname) {
                    Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Group.Name)" -Recurse -Force
                }
            }
        }
        #Endregion Helper-Functions
    }

    process {
        # Prompt for confirmation before proceeding
        if ($PSCmdlet.ShouldProcess('This PC', 'Removing the Hardening Measures Applied by the Protect-WindowsSecurity Cmdlet')) {

            # doing a try-finally block on the entire script so that when CTRL + C is pressed to forcefully exit the script,
            # or break is passed, clean up will still happen for secure exit
            try {

                $CurrentMainStep++
                Write-Progress -Id 0 -Activity 'Backing up Controlled Folder Access exclusion list' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                # backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
                # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
                # no user customization will be affected
                [System.String[]]$CFAAllowedAppsBackup = ([HardeningModule.GlobalVars]::MDAVPreferencesCurrent).ControlledFolderAccessAllowedApplications

                # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
                # so that the script can run without interruption. This change is reverted at the end.
                foreach ($FilePath in (Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) {
                    Add-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
                }

                Start-Sleep -Seconds 3

                Switch ($True) {
                    $OnlyCountryIPBlockingFirewallRules {
                        # Normally these are removed when all group policies are removed, but in case only the firewall rules are removed
                        Write-Verbose -Message 'Removing the country IP blocking firewall rules only'
                        Remove-NetFirewallRule -DisplayName 'OFAC Sanctioned Countries IP range blocking' -PolicyStore localhost -ErrorAction SilentlyContinue
                        Remove-NetFirewallRule -DisplayName 'State Sponsors of Terrorism IP range blocking' -PolicyStore localhost -ErrorAction SilentlyContinue
                        Start-Process -FilePath GPUpdate.exe -ArgumentList '/force' -NoNewWindow
                        break
                    }
                    { $WDACPoliciesToRemove.count -gt 0 } {
                        Remove-WDACPolicies -PolicyNames $WDACPoliciesToRemove
                        break
                    }
                    $OnlyProcessMitigations {
                        Remove-ProcessMitigations
                        break
                    }
                    default {
                        $CurrentMainStep++
                        Write-Progress -Id 0 -Activity 'Removing WDAC Policies' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                        Remove-WDACPolicies -PolicyNames ('Downloads-Defense-Measures', 'Dangerous-Script-Hosts-Blocking')

                        # change location to the new directory
                        Write-Verbose -Message 'Changing location'
                        Set-Location -Path ([HardeningModule.GlobalVars]::WorkingDir)

                        $CurrentMainStep++
                        Write-Progress -Id 0 -Activity 'Removing Process Mitigations for apps' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)
                        Remove-ProcessMitigations

                        $CurrentMainStep++
                        Write-Progress -Id 0 -Activity 'Deleting all group policies' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                        if (Test-Path -Path "$env:SystemDrive\Windows\System32\GroupPolicy") {
                            Remove-Item -Path "$env:SystemDrive\Windows\System32\GroupPolicy" -Recurse -Force
                        }

                        $CurrentMainStep++
                        Write-Progress -Id 0 -Activity 'Deleting all the registry keys created by the Protect-WindowsSecurity cmdlet' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                        foreach ($Item in ([HardeningModule.GlobalVars]::RegistryCSVItems)) {
                            [HardeningModule.RegistryEditor]::EditRegistry($Item.Path, $Item.Key, $Item.Value, $Item.Type, 'Delete')
                        }

                        # To completely remove the Edge policy since only its sub-keys are removed by the command above
                        Remove-Item -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge\TLSCipherSuiteDenyList' -Force -Recurse -ErrorAction SilentlyContinue

                        # Restore Security group policies back to their default states

                        $CurrentMainStep++
                        Write-Progress -Id 0 -Activity 'Restoring the default Security group policies' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                        # Download LGPO program from Microsoft servers
                        Invoke-WebRequest -Uri 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip' -OutFile '.\LGPO.zip' -ProgressAction SilentlyContinue -HttpVersion '3.0' -SslProtocol 'Tls12,Tls13'

                        # unzip the LGPO file
                        Expand-Archive -Path .\LGPO.zip -DestinationPath .\ -Force
                        .\'LGPO_30\LGPO.exe' /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Default Security Policy.inf"

                        # Enable LMHOSTS lookup protocol on all network adapters again
                        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name 'EnableLMHOSTS' -Value '1' -Type DWord

                        # Disable restart notification for Windows update
                        Set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -Name 'RestartNotificationsAllowed2' -Value '0' -Type DWord

                        # Re-enables the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines
                        $null = SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable

                        $CurrentMainStep++
                        Write-Progress -Id 0 -Activity 'Restoring Microsoft Defender configs back to their default states' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                        # Disable the advanced new security features of the Microsoft Defender
                        Set-MpPreference -AllowSwitchToAsyncInspection $False
                        Set-MpPreference -OobeEnableRtpAndSigUpdate $False
                        Set-MpPreference -IntelTDTEnabled $False
                        Set-MpPreference -DisableRestorePoint $True
                        Set-MpPreference -PerformanceModeStatus Enabled
                        Set-MpPreference -EnableConvertWarnToBlock $False
                        Set-MpPreference -EngineUpdatesChannel NotConfigured
                        Set-MpPreference -PlatformUpdatesChannel NotConfigured
                        Set-MpPreference -BruteForceProtectionAggressiveness 0
                        Set-MpPreference -BruteForceProtectionConfiguredState 0
                        Set-MpPreference -BruteForceProtectionMaxBlockTime 0
                        Set-MpPreference -RemoteEncryptionProtectionAggressiveness 0
                        Set-MpPreference -RemoteEncryptionProtectionConfiguredState 0
                        Set-MpPreference -RemoteEncryptionProtectionMaxBlockTime 0

                        # Set Data Execution Prevention (DEP) back to its default value
                        Set-BcdElement -Element 'nx' -Type 'Integer' -Value '0'

                        # Remove the scheduled task that keeps the Microsoft recommended driver block rules updated

                        # Define the name and path of the task
                        [System.String]$TaskName = 'MSFT Driver Block list update'
                        [System.String]$TaskPath = '\MSFT Driver Block list update\'

                        Write-Verbose -Message "Removing the scheduled task $TaskName"
                        if (Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue) {
                            [System.Void](Unregister-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Confirm:$false)
                        }

                        # Enables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles
                        foreach ($FirewallRule in Get-NetFirewallRule) {
                            if ($FirewallRule.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302' -and $FirewallRule.Direction -eq 'inbound') {
                                foreach ($Item in $FirewallRule) {
                                    Enable-NetFirewallRule -DisplayName $Item.DisplayName
                                }
                            }
                        }

                        # Remove any custom views added by this script for Event Viewer
                        if ([System.IO.Directory]::Exists("$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script")) {
                            Remove-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Recurse -Force
                        }

                        # Set a tattooed Group policy for Svchost.exe process mitigations back to disabled state
                        Set-ItemProperty -Path 'Registry::\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SCMConfig' -Name 'EnableSvchostMitigationPolicy' -Value '0' -Force -Type 'DWord' -ErrorAction SilentlyContinue
                    }
                }

                # Write in Fuchsia color
                Write-Host -Object "$($PSStyle.Foreground.FromRGB(236,68,155))Operation Completed, please restart your computer.$($PSStyle.Reset)"
            }
            finally {
                Write-Verbose -Message 'Finally block is running'

                # End the progress bar and mark it as completed
                Write-Progress -Id 0 -Activity 'Completed' -Completed

                # Reverting the PowerShell executables allow listings in Controlled folder access
                foreach ($FilePath in (Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) {
                    Remove-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
                }

                # restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
                # they will be restored as well, so user customization will remain intact
                if ($null -ne $CFAAllowedAppsBackup) {
                    Set-MpPreference -ControlledFolderAccessAllowedApplications $CFAAllowedAppsBackup
                }

                Set-Location -Path $HOME

                [HardeningModule.Miscellaneous]::CleanUp()
            }
        }
    }

    <#
.SYNOPSIS
    Removes the hardening measures applied by Protect-WindowsSecurity cmdlet
.LINK
    https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden%E2%80%90Windows%E2%80%90Security%E2%80%90Module
.DESCRIPTION
    Removes the hardening measures applied by Protect-WindowsSecurity cmdlet
.COMPONENT
    PowerShell
.FUNCTIONALITY
    Removes the hardening measures applied by Protect-WindowsSecurity cmdlet
.PARAMETER OnlyProcessMitigations
    Only removes the Process Mitigations / Exploit Protection settings and doesn't change anything else
.PARAMETER WDACPoliciesToRemove
    Names of the WDAC Policies to remove
.PARAMETER OnlyCountryIPBlockingFirewallRules
    Only removes the country IP blocking firewall rules and doesn't change anything else
.PARAMETER Force
    Suppresses the confirmation prompt
.EXAMPLE
    Unprotect-WindowsSecurity

    Removes all of the security features applied by the Protect-WindowsSecurity cmdlet
.EXAMPLE
    Unprotect-WindowsSecurity -OnlyProcessMitigations

    Removes only the Process Mitigations / Exploit Protection settings and doesn't change anything else
.EXAMPLE
    Unprotect-WindowsSecurity -Force

    Removes all of the security features applied by the Protect-WindowsSecurity cmdlet without prompting for confirmation
.INPUTS
    System.Management.Automation.SwitchParameter
    System.String[]
.OUTPUTS
    System.String
#>
}
