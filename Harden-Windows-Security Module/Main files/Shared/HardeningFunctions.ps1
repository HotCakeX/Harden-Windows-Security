$script:ErrorActionPreference = 'Stop'
function Select-Option {
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $True)][System.String]$Message,
        [parameter(Mandatory = $True)][System.String[]]$Options,
        [parameter(Mandatory = $false)][Switch]$SubCategory,
        [parameter(Mandatory = $false)][System.String]$ExtraMessage
    )
    $Selected = $null
    while ($null -eq $Selected) {
        if (!$SubCategory) { Write-ColorfulText -Color Fuchsia -I $Message }
        else {
            Write-ColorfulText -Color Orange -I $Message
            if ($ExtraMessage) { Write-ColorfulText -Color PinkBoldBlink -I $ExtraMessage }
        }

        for ($I = 0; $I -lt $Options.Length; $I++) {
            Write-ColorfulText -Color MintGreen -I "$($I+1): $($Options[$I])"
        }

        [System.Int64]$SelectedIndex = 0
        $IsValid = [System.Int64]::TryParse((Read-Host -Prompt 'Select an option'), [ref]$SelectedIndex)
        if ($IsValid) {
            if ($SelectedIndex -gt 0 -and $SelectedIndex -le $Options.Length) {
                $Selected = $Options[$SelectedIndex - 1]
            }
            else { Write-Warning -Message 'Invalid Option.' }
        }
        else { Write-Warning -Message 'Invalid input. Please only enter a positive number.' }
    }
    [HardenWindowsSecurity.Logger]::LogMessage("Selected: $Selected", [HardenWindowsSecurity.LogTypeIntel]::Information)
    return [System.String]$Selected
}
function Write-ColorfulText {
    param (
        [Parameter(Mandatory = $True)][ValidateSet('Fuchsia', 'Orange', 'MintGreen', 'PinkBoldBlink', 'Plum')][System.String]$Color,
        [parameter(Mandatory = $True)][System.String]$InputText
    )
    switch ($Color) {
        'Fuchsia' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(236,68,155))$InputText$($PSStyle.Reset)"; break }
        'Orange' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(255,165,0))$InputText$($PSStyle.Reset)"; break }
        'MintGreen' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(152,255,152))$InputText$($PSStyle.Reset)"; break }
        'Plum' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(221,160,221))$($PSStyle.Bold)$InputText$($PSStyle.Reset)"; break }
        'PinkBoldBlink' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Blink)$InputText$($PSStyle.Reset)"; break }
        default { throw 'Unspecified Color' }
    }
}
function Invoke-MicrosoftSecurityBaselines {
    param([Switch]$RunUnattended)
    :MicrosoftSecurityBaselinesCategoryLabel switch ($RunUnattended ? ($SecBaselines_NoOverrides ? 'Yes' : 'Yes, With the Optional Overrides (Recommended)') : (Select-Option -Options 'Yes', 'Yes, With the Optional Overrides (Recommended)' , 'No', 'Exit' -Message "`nApply Microsoft Security Baseline ?")) {
        'Yes' { [HardenWindowsSecurity.MicrosoftSecurityBaselines]::Invoke() }
        'Yes, With the Optional Overrides (Recommended)' {
            [HardenWindowsSecurity.MicrosoftSecurityBaselines]::Invoke()
            [HardenWindowsSecurity.MicrosoftSecurityBaselines]::SecBaselines_Overrides()
        }
        'No' { break MicrosoftSecurityBaselinesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-Microsoft365AppsSecurityBaselines {
    param([Switch]$RunUnattended)
    :Microsoft365AppsSecurityBaselinesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Microsoft 365 Apps Security Baseline ?")) {
        'Yes' {
            [HardenWindowsSecurity.Microsoft365AppsSecurityBaselines]::Invoke()
        } 'No' { break Microsoft365AppsSecurityBaselinesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-MicrosoftDefender {
    param([Switch]$RunUnattended)
    :MicrosoftDefenderLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Microsoft Defender category ?")) {
        'Yes' {
            [HardenWindowsSecurity.MicrosoftDefender]::Invoke()

            # Suggest turning on Smart App Control only if it's in Eval mode
            if (([HardenWindowsSecurity.GlobalVars]::MDAVConfigCurrent).SmartAppControlState -eq 'Eval') {
                :SmartAppControlLabel switch ($RunUnattended ? ($MSFTDefender_SAC ? 'Yes' : 'No' ) : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nTurn on Smart App Control ?")) {
                    'Yes' {
                        [HardenWindowsSecurity.MicrosoftDefender]::MSFTDefender_SAC()
                    } 'No' { break SmartAppControlLabel }
                    'Exit' { break MainSwitchLabel }
                }
            }

            if ((([HardenWindowsSecurity.GlobalVars]::ShouldEnableOptionalDiagnosticData) -eq $True) -or (([HardenWindowsSecurity.GlobalVars]::MDAVConfigCurrent).SmartAppControlState -eq 'On')) {
                [HardenWindowsSecurity.Logger]::LogMessage('Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on', [HardenWindowsSecurity.LogTypeIntel]::Information)
                [HardenWindowsSecurity.MicrosoftDefender]::MSFTDefender_EnableDiagData()
            }
            else {
                # Ask user if they want to turn on optional diagnostic data only if Smart App Control is not already turned off
                if (([HardenWindowsSecurity.GlobalVars]::MDAVConfigCurrent).SmartAppControlState -ne 'Off') {
                    :SmartAppControlLabel2 switch ($RunUnattended ? ($MSFTDefender_NoDiagData ? 'No' : 'Yes') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Optional Diagnostic Data ?" -ExtraMessage 'Required for Smart App Control usage and evaluation, read the GitHub Readme!')) {
                        'Yes' {
                            [HardenWindowsSecurity.MicrosoftDefender]::MSFTDefender_EnableDiagData()
                        } 'No' { break SmartAppControlLabel2 }
                        'Exit' { break MainSwitchLabel }
                    }
                }
                else {
                    [HardenWindowsSecurity.Logger]::LogMessage('Smart App Control is turned off, so Optional Diagnostic Data will not be enabled', [HardenWindowsSecurity.LogTypeIntel]::Information)
                }
            }

            # Create scheduled task for fast weekly Microsoft recommended driver block list update. The method will overwrite the task if it exists which is the desired behavior.
            :TaskSchedulerCreationLabel switch ($RunUnattended ? ($MSFTDefender_NoScheduledTask ? 'No' : 'Yes') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nCreate scheduled task for fast weekly Microsoft recommended driver block list update ?")) {
                'Yes' {
                    [HardenWindowsSecurity.MicrosoftDefender]::MSFTDefender_ScheduledTask()
                } 'No' { break TaskSchedulerCreationLabel }
                'Exit' { break MainSwitchLabel }
            }

            # Only display this prompt if Engine and Platform update channels are not already set to Beta
            if ((([HardenWindowsSecurity.GlobalVars]::MDAVPreferencesCurrent).EngineUpdatesChannel -ne '2') -or (([HardenWindowsSecurity.GlobalVars]::MDAVPreferencesCurrent).PlatformUpdatesChannel -ne '2')) {
                # Set Microsoft Defender engine and platform update channel to beta - Devices in the Windows Insider Program are subscribed to this channel by default.
                :DefenderUpdateChannelsLabel switch ($RunUnattended ? ($MSFTDefender_BetaChannels ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nSet Microsoft Defender engine and platform update channel to beta ?")) {
                    'Yes' {
                        [HardenWindowsSecurity.MicrosoftDefender]::MSFTDefender_BetaChannels()
                    } 'No' { break DefenderUpdateChannelsLabel }
                    'Exit' { break MainSwitchLabel }
                }
            }
            else {
                [HardenWindowsSecurity.Logger]::LogMessage('Microsoft Defender engine and platform update channel is already set to beta', [HardenWindowsSecurity.LogTypeIntel]::Information)
            }
        } 'No' { break MicrosoftDefenderLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-AttackSurfaceReductionRules {
    param([Switch]$RunUnattended)
    :ASRRulesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Attack Surface Reduction Rules category ?")) {
        'Yes' {
            [HardenWindowsSecurity.AttackSurfaceReductionRules]::Invoke()
        } 'No' { break ASRRulesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-BitLockerSettings {
    param([Switch]$RunUnattended)
    :BitLockerCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Bitlocker category ?")) {
        'Yes' {
            [HardenWindowsSecurity.BitLockerSettings]::Invoke()
        } 'No' { break BitLockerCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-DeviceGuard {
    param([Switch]$RunUnattended)
    :DeviceGuardCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Device Guard category ?")) {
        'Yes' {
            [HardenWindowsSecurity.DeviceGuard]::Invoke()
            :DeviceGuard_MandatoryVBS switch ($RunUnattended ? ($DeviceGuard_MandatoryVBS ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable VBS and Memory Integrity in Mandatory Mode ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.DeviceGuard]::DeviceGuard_MandatoryVBS()
                } 'No' { break DeviceGuard_MandatoryVBS }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break DeviceGuardCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-TLSSecurity {
    param([Switch]$RunUnattended)
    :TLSSecurityLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun TLS Security category ?")) {
        'Yes' {
            [HardenWindowsSecurity.TLSSecurity]::Invoke()
        } 'No' { break TLSSecurityLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-LockScreen {
    param([Switch]$RunUnattended)
    :LockScreenLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Lock Screen category ?")) {
        'Yes' {
            [HardenWindowsSecurity.LockScreen]::Invoke()
            :LockScreenLastSignedInLabel switch ($RunUnattended ? ($LockScreen_NoLastSignedIn ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nDon't display last signed-in on logon screen ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.LockScreen]::LockScreen_LastSignedIn()
                } 'No' { break LockScreenLastSignedInLabel }
                'Exit' { break MainSwitchLabel }
            }
            :CtrlAltDelLabel switch ($RunUnattended ? ($LockScreen_CtrlAltDel ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable requiring CTRL + ALT + DEL on lock screen ?")) {
                'Yes' {
                    [HardenWindowsSecurity.LockScreen]::LockScreen_CtrlAltDel()
                } 'No' { break CtrlAltDelLabel }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break LockScreenLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-UserAccountControl {
    param([Switch]$RunUnattended)
    :UACLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun User Account Control category ?")) {
        'Yes' {
            [HardenWindowsSecurity.UserAccountControl]::Invoke()
            :FastUserSwitchingLabel switch ($RunUnattended ? ($UAC_NoFastSwitching ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nHide the entry points for Fast User Switching ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.UserAccountControl]::UAC_NoFastSwitching()
                } 'No' { break FastUserSwitchingLabel }
                'Exit' { break MainSwitchLabel }
            }
            :ElevateSignedExeLabel switch ($RunUnattended ? ($UAC_OnlyElevateSigned ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nOnly elevate executables that are signed and validated ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.UserAccountControl]::UAC_OnlyElevateSigned()
                } 'No' { break ElevateSignedExeLabel }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break UACLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-WindowsFirewall {
    param([Switch]$RunUnattended)
    :WindowsFirewallLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Firewall category ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsFirewall]::Invoke()
        } 'No' { break WindowsFirewallLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-OptionalWindowsFeatures {
    param([Switch]$RunUnattended)
    :OptionalFeaturesLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Optional Windows Features category ?")) {
        'Yes' {
            [HardenWindowsSecurity.OptionalWindowsFeatures]::Invoke()
        } 'No' { break OptionalFeaturesLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-WindowsNetworking {
    param([Switch]$RunUnattended)
    :WindowsNetworkingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Networking category ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsNetworking]::Invoke()
            :WindowsNetworking_BlockNTLMLabel switch ($RunUnattended ? ($WindowsNetworking_BlockNTLM ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nBlock NTLM Completely ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.WindowsNetworking]::WindowsNetworking_BlockNTLM()
                } 'No' { break WindowsNetworking_BlockNTLMLabel }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break WindowsNetworkingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-MiscellaneousConfigurations {
    param([Switch]$RunUnattended)
    :MiscellaneousLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Miscellaneous Configurations category ?")) {
        'Yes' {
            [HardenWindowsSecurity.MiscellaneousConfigurations]::Invoke()
            :Miscellaneous_WindowsProtectedPrintLabel switch ($RunUnattended ? ($Miscellaneous_WindowsProtectedPrint ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Windows Protected Print ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.MiscellaneousConfigurations]::MiscellaneousConfigurations_WindowsProtectedPrint()
                } 'No' { break Miscellaneous_WindowsProtectedPrintLabel }
                'Exit' { break MainSwitchLabel }
            }
            :MiscellaneousConfigurations_LongPathSupport switch ($RunUnattended ? ($MiscellaneousConfigurations_LongPathSupport ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Long path support for programs ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.MiscellaneousConfigurations]::MiscellaneousConfigurations_LongPathSupport()
                } 'No' { break MiscellaneousConfigurations_LongPathSupport }
                'Exit' { break MainSwitchLabel }
            }
            :MiscellaneousConfigurations_StrongKeyProtection switch ($RunUnattended ? ($MiscellaneousConfigurations_StrongKeyProtection ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnforce strong key protection ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.MiscellaneousConfigurations]::MiscellaneousConfigurations_StrongKeyProtection()
                } 'No' { break MiscellaneousConfigurations_StrongKeyProtection }
                'Exit' { break MainSwitchLabel }
            }
            :MiscellaneousConfigurations_ReducedTelemetry switch ($RunUnattended ? ($MiscellaneousConfigurations_ReducedTelemetry ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nApply policies that reduce telemetry in the OS ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.MiscellaneousConfigurations]::MiscellaneousConfigurations_ReducedTelemetry()
                } 'No' { break MiscellaneousConfigurations_ReducedTelemetry }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break MiscellaneousLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-WindowsUpdateConfigurations {
    param([Switch]$RunUnattended)
    :WindowsUpdateLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Windows Update Policies ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsUpdateConfigurations]::Invoke()
        } 'No' { break WindowsUpdateLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-EdgeBrowserConfigurations {
    param([Switch]$RunUnattended)
    :MSEdgeLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Edge Browser Configurations ?")) {
        'Yes' {
            [HardenWindowsSecurity.EdgeBrowserConfigurations]::Invoke()
        } 'No' { break MSEdgeLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-CertificateCheckingCommands {
    param([Switch]$RunUnattended)
    :CertCheckingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Certificate Checking category ?")) {
        'Yes' {
            [HardenWindowsSecurity.CertificateCheckingCommands]::Invoke()
        } 'No' { break CertCheckingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-CountryIPBlocking {
    param(
        [Switch]$RunUnattended
    )
    :IPBlockingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Country IP Blocking category ?")) {
        'Yes' {
            :IPBlockingTerrLabel switch ($RunUnattended ? 'Yes' : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add countries in the State Sponsors of Terrorism list to the Firewall block list?')) {
                'Yes' {
                    [HardenWindowsSecurity.CountryIPBlocking]::Invoke()
                } 'No' { break IPBlockingTerrLabel }
            }
            :IPBlockingOFACLabel switch ($RunUnattended ? ($CountryIPBlocking_OFAC ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add OFAC Sanctioned Countries to the Firewall block list?')) {
                'Yes' {
                    [HardenWindowsSecurity.CountryIPBlocking]::CountryIPBlocking_OFAC()
                } 'No' { break IPBlockingOFACLabel }
            }
        } 'No' { break IPBlockingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-DownloadsDefenseMeasures {
    param([Switch]$RunUnattended)
    :DownloadsDefenseMeasuresLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Downloads Defense Measures category ?")) {
        'Yes' {
            [HardenWindowsSecurity.DownloadsDefenseMeasures]::Invoke()
            :DangerousScriptHostsBlockingLabel switch ($RunUnattended ? ($DangerousScriptHostsBlocking ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Deploy the Dangerous Script Hosts Blocking AppControl Policy?')) {
                'Yes' {
                    [HardenWindowsSecurity.DownloadsDefenseMeasures]::DangerousScriptHostsBlocking()
                } 'No' { break DangerousScriptHostsBlockingLabel }
            }
        } 'No' { break DownloadsDefenseMeasuresLabel }
        'Exit' { break MainSwitchLabel }
    }
}
function Invoke-NonAdminCommands {
    param([Switch]$RunUnattended)
    :NonAdminLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Non-Admin category ?")) {
        'Yes' {
            [HardenWindowsSecurity.NonAdminCommands]::Invoke()
        } 'No' { break NonAdminLabel }
        'Exit' { break MainSwitchLabel }
    }
}