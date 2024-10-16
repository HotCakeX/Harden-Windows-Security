$script:ErrorActionPreference = 'Stop'

#Region Helper-Functions
Function Select-Option {
    <#
    .synopsis
        Function to show a prompt to the user to select an option from a list of options
    .INPUTS
        System.String
        System.Management.Automation.SwitchParameter
    .OUTPUTS
        System.String
    .PARAMETER Message
        Contains the main prompt message
    .PARAMETER ExtraMessage
        Contains any extra notes for sub-categories
    #>
    [CmdletBinding()]
    param(
        [parameter(Mandatory = $True)][System.String]$Message,
        [parameter(Mandatory = $True)][System.String[]]$Options,
        [parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$SubCategory,
        [parameter(Mandatory = $false)][System.String]$ExtraMessage
    )

    $Selected = $null
    while ($null -eq $Selected) {

        # Use this style if showing main categories only
        if (!$SubCategory) {
            Write-ColorfulText -C Fuchsia -I $Message
        }
        # Use this style if showing sub-categories only that need additional confirmation
        else {
            # Show sub-category's main prompt
            Write-ColorfulText -C Orange -I $Message
            # Show sub-category's notes/extra message if any
            if ($ExtraMessage) {
                Write-ColorfulText -C PinkBoldBlink -I $ExtraMessage
            }
        }

        for ($I = 0; $I -lt $Options.Length; $I++) {
            Write-ColorfulText -C MintGreen -I "$($I+1): $($Options[$I])"
        }

        # Make sure user only inputs a positive integer
        [System.Int64]$SelectedIndex = 0
        $IsValid = [System.Int64]::TryParse((Read-Host -Prompt 'Select an option'), [ref]$SelectedIndex)
        if ($IsValid) {
            if ($SelectedIndex -gt 0 -and $SelectedIndex -le $Options.Length) {
                $Selected = $Options[$SelectedIndex - 1]
            }
            else {
                Write-Warning -Message 'Invalid Option.'
            }
        }
        else {
            Write-Warning -Message 'Invalid input. Please only enter a positive number.'
        }
    }
    # Add verbose output, helpful when reviewing the log file
    [HardenWindowsSecurity.Logger]::LogMessage("Selected: $Selected", [HardenWindowsSecurity.LogTypeIntel]::Information)
    return [System.String]$Selected
}
Function Write-ColorfulText {
    <#
    .SYNOPSIS
        Function to write colorful text to the console
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [Alias('C')]
        [ValidateSet('Fuchsia', 'Orange', 'NeonGreen', 'MintGreen', 'PinkBoldBlink', 'PinkBold', 'Rainbow' , 'Gold', 'TeaGreenNoNewLine', 'LavenderNoNewLine', 'PinkNoNewLine', 'VioletNoNewLine', 'Violet', 'Pink', 'Lavender')]
        [System.String]$Color,

        [parameter(Mandatory = $True)]
        [Alias('I')]
        [System.String]$InputText
    )
    switch ($Color) {
        'Fuchsia' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(236,68,155))$InputText$($PSStyle.Reset)"; break }
        'Orange' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(255,165,0))$InputText$($PSStyle.Reset)"; break }
        'NeonGreen' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(153,244,67))$InputText$($PSStyle.Reset)"; break }
        'MintGreen' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(152,255,152))$InputText$($PSStyle.Reset)"; break }
        'PinkBoldBlink' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Blink)$InputText$($PSStyle.Reset)"; break }
        'PinkBold' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,192,203))$($PSStyle.Bold)$($PSStyle.Reverse)$InputText$($PSStyle.Reset)"; break }
        'Gold' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,215,0))$InputText$($PSStyle.Reset)"; break }
        'VioletNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(153,0,255))$InputText$($PSStyle.Reset)" -NoNewline; break }
        'PinkNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(255,0,230))$InputText$($PSStyle.Reset)" -NoNewline; break }
        'Violet' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(153,0,255))$InputText$($PSStyle.Reset)"; break }
        'Pink' { Write-Host -Object "$($PSStyle.Foreground.FromRGB(255,0,230))$InputText$($PSStyle.Reset)"; break }
        'LavenderNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,179,255))$InputText$($PSStyle.Reset)" -NoNewline; break }
        'Lavender' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(255,179,255))$InputText$($PSStyle.Reset)"; break }
        'TeaGreenNoNewLine' { Write-Host -Object "$($PSStyle.Foreground.FromRgb(133, 222, 119))$InputText$($PSStyle.Reset)" -NoNewline; break }
        'Rainbow' {
            [System.Drawing.Color[]]$RainbowColors = @(
                [System.Drawing.Color]::Pink,
                [System.Drawing.Color]::HotPink,
                [System.Drawing.Color]::SkyBlue,
                [System.Drawing.Color]::HotPink,
                [System.Drawing.Color]::SkyBlue,
                [System.Drawing.Color]::LightSkyBlue,
                [System.Drawing.Color]::LightGreen,
                [System.Drawing.Color]::Coral,
                [System.Drawing.Color]::Plum,
                [System.Drawing.Color]::Gold
            )

            $StringBuilder = [System.Text.StringBuilder]::new()
            for ($I = 0; $I -lt $InputText.Length; $I++) {
                $CurrentColor = $RainbowColors[$I % $RainbowColors.Length]
                [System.Void]$StringBuilder.Append("$($PSStyle.Foreground.FromRGB($CurrentColor.R, $CurrentColor.G, $CurrentColor.B))$($PSStyle.Blink)$($InputText[$I])$($PSStyle.BlinkOff)$($PSStyle.Reset)")
            }
            Write-Output -InputObject $StringBuilder.ToString()
            break
        }
        Default { Throw 'Unspecified Color' }
    }
}
#Endregion Helper-Functions

#Region Hardening-Categories-Functions
Function Invoke-MicrosoftSecurityBaselines {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :MicrosoftSecurityBaselinesCategoryLabel switch ($RunUnattended ? ($SecBaselines_NoOverrides ? 'Yes' : 'Yes, With the Optional Overrides (Recommended)') : (Select-Option -Options 'Yes', 'Yes, With the Optional Overrides (Recommended)' , 'No', 'Exit' -Message "`nApply Microsoft Security Baseline ?")) {
        'Yes' {
            [HardenWindowsSecurity.MicrosoftSecurityBaselines]::Invoke()
        }
        'Yes, With the Optional Overrides (Recommended)' {
            [HardenWindowsSecurity.MicrosoftSecurityBaselines]::Invoke()
            [HardenWindowsSecurity.MicrosoftSecurityBaselines]::SecBaselines_Overrides()
        }
        'No' { break MicrosoftSecurityBaselinesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-Microsoft365AppsSecurityBaselines {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :Microsoft365AppsSecurityBaselinesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Microsoft 365 Apps Security Baseline ?")) {
        'Yes' {
            [HardenWindowsSecurity.Microsoft365AppsSecurityBaselines]::Invoke()
        } 'No' { break Microsoft365AppsSecurityBaselinesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-MicrosoftDefender {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
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
Function Invoke-AttackSurfaceReductionRules {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :ASRRulesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Attack Surface Reduction Rules category ?")) {
        'Yes' {
            [HardenWindowsSecurity.AttackSurfaceReductionRules]::Invoke()
        } 'No' { break ASRRulesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-BitLockerSettings {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :BitLockerCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Bitlocker category ?")) {
        'Yes' {
            [HardenWindowsSecurity.BitLockerSettings]::Invoke()
        } 'No' { break BitLockerCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-DeviceGuard {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :DeviceGuardCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Device Guard category ?")) {
        'Yes' {
            [HardenWindowsSecurity.DeviceGuard]::Invoke()
        } 'No' { break DeviceGuardCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-TLSSecurity {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :TLSSecurityLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun TLS Security category ?")) {
        'Yes' {
            [HardenWindowsSecurity.TLSSecurity]::Invoke()
        } 'No' { break TLSSecurityLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-LockScreen {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
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
Function Invoke-UserAccountControl {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
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
Function Invoke-WindowsFirewall {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :WindowsFirewallLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Firewall category ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsFirewall]::Invoke()
        } 'No' { break WindowsFirewallLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-OptionalWindowsFeatures {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :OptionalFeaturesLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Optional Windows Features category ?")) {
        'Yes' {
            [HardenWindowsSecurity.OptionalWindowsFeatures]::Invoke()
        } 'No' { break OptionalFeaturesLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-WindowsNetworking {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
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
Function Invoke-MiscellaneousConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :MiscellaneousLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Miscellaneous Configurations category ?")) {
        'Yes' {
            [HardenWindowsSecurity.MiscellaneousConfigurations]::Invoke()
            :Miscellaneous_WindowsProtectedPrintLabel switch ($RunUnattended ? ($Miscellaneous_WindowsProtectedPrint ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Windows Protected Print ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    [HardenWindowsSecurity.MiscellaneousConfigurations]::MiscellaneousConfigurations_WindowsProtectedPrint()
                } 'No' { break Miscellaneous_WindowsProtectedPrintLabel }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break MiscellaneousLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-WindowsUpdateConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :WindowsUpdateLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Windows Update Policies ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsUpdateConfigurations]::Invoke()
        } 'No' { break WindowsUpdateLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-EdgeBrowserConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :MSEdgeLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Edge Browser Configurations ?")) {
        'Yes' {
            [HardenWindowsSecurity.EdgeBrowserConfigurations]::Invoke()
        } 'No' { break MSEdgeLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-CertificateCheckingCommands {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :CertCheckingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Certificate Checking category ?")) {
        'Yes' {
            [HardenWindowsSecurity.CertificateCheckingCommands]::Invoke()
        } 'No' { break CertCheckingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-CountryIPBlocking {
    param(
        [System.Management.Automation.SwitchParameter]$RunUnattended
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
Function Invoke-DownloadsDefenseMeasures {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
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
Function Invoke-NonAdminCommands {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    :NonAdminLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Non-Admin category ?")) {
        'Yes' {
            [HardenWindowsSecurity.NonAdminCommands]::Invoke()
            # Only suggest restarting the device if Admin related categories were run and the code was not running in unattended mode
            if (!$RunUnattended) {
                if (!$Categories -and [HardenWindowsSecurity.UserPrivCheck]::IsAdmin()) {
                    Write-Host -Object "`r`n"
                    Write-ColorfulText -C Rainbow -I "################################################################################################`r`n"
                    Write-ColorfulText -C MintGreen -I "###  Please Restart your device to completely apply the security measures and Group Policies ###`r`n"
                    Write-ColorfulText -C Rainbow -I "################################################################################################`r`n"
                }
            }
        } 'No' { break NonAdminLabel }
        'Exit' { break MainSwitchLabel }
    }
}
#Endregion Hardening-Categories-Functions
