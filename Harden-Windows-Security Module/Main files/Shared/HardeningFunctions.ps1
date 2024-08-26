$script:ErrorActionPreference = 'Stop'

#Region Helper-Functions-And-ScriptBlocks
# The following functions do not rely on any script-wide or global variables
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
    Write-Verbose -Message "Selected: $Selected"
    return [System.String]$Selected
}
Function Write-ColorfulText {
    <#
    .SYNOPSIS
        Function to write colorful text to the console
    .INPUTS
        System.String
        System.Management.Automation.SwitchParameter
    .OUTPUTS
        System.String
    .PARAMETER Color
        The color to use to display the text, uses PSStyle
     .PARAMETER InputText
        The text to display in the selected color
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
Function Get-AvailableRemovableDrives {
    <#
    .SYNOPSIS
        Function to get a removable drive to be used by BitLocker category
    .INPUTS
        None. You cannot pipe objects to this function
    .OUTPUTS
        System.String
    #>

    # An empty array of objects that holds the final removable drives list
    [System.Object[]]$AvailableRemovableDrives = @()

    Get-Volume | Where-Object -FilterScript { $_.DriveLetter -and $_.DriveType -eq 'Removable' } |
    ForEach-Object -Process {

        # Prepare to create an extremely random file name
        [System.String]$Path = "$($_.DriveLetter + ':')\$(New-Guid).$(Get-Random -Maximum 400)"

        try {
            # Create a test file on the drive to make sure it's not write-protected
            $null = New-Item -Path $Path -ItemType File -Value 'test' -Force
            # If the drive wasn't write-protected then delete the test file
            Remove-Item -Path $Path -Force
            # Add the drive to the list only if it's writable
            $AvailableRemovableDrives += $_
        }
        catch {
            # Drive is write protected, do nothing
        }

    }

    # If there is any Writable removable drives, sort and prepare them and then add them to the array
    if ($AvailableRemovableDrives) {
        $AvailableRemovableDrives = $AvailableRemovableDrives | Sort-Object -Property DriveLetter |
        Select-Object -Property DriveLetter, FileSystemType, DriveType, @{Name = 'Size'; Expression = { '{0:N2}' -f ($_.Size / 1GB) + ' GB' } }
    }

    if (!$AvailableRemovableDrives) {
        do {
            switch (Select-Option -Options 'Check for removable flash drives again', 'Skip encryptions altogether', 'Exit' -Message "`nNo removable writable flash drives found. Please insert a USB flash drive. If it's already attached to the system, try ejecting it and inserting it back in.") {
                'Check for removable flash drives again' {

                    # An empty array of objects that holds the final removable drives list
                    [System.Object[]]$AvailableRemovableDrives = @()

                    Get-Volume | Where-Object -FilterScript { $_.DriveLetter -and $_.DriveType -eq 'Removable' } |
                    ForEach-Object -Process {

                        # Prepare to create an extremely random file name
                        [System.String]$ExtremelyRandomPath = "$($_.DriveLetter + ':')\$(New-Guid).$(Get-Random -Maximum 400)"

                        try {
                            # Create a test file on the drive to make sure it's not write-protected
                            $null = New-Item -Path $ExtremelyRandomPath -ItemType File -Value 'test' -Force
                            # If the drive wasn't write-protected then delete the test file
                            Remove-Item -Path $ExtremelyRandomPath -Force
                            # Add the drive to the list only if it's writable
                            $AvailableRemovableDrives += $_
                        }
                        catch {
                            # Drive is write protected, do nothing
                        }
                    }

                    # If there is any Writable removable drives, sort and prepare them and then add them to the array
                    if ($AvailableRemovableDrives) {
                        $AvailableRemovableDrives = $AvailableRemovableDrives | Sort-Object -Property DriveLetter |
                        Select-Object -Property DriveLetter, FileSystemType, DriveType, @{Name = 'Size'; Expression = { '{0:N2}' -f ($_.Size / 1GB) + ' GB' } }
                    }

                }
                'Skip encryptions altogether' { break BitLockerCategoryLabel } # Breaks from the BitLocker category and won't process Non-OS Drives
                'Exit' { break MainSwitchLabel }
            }
        }
        until ($AvailableRemovableDrives)
    }

    # Initialize the maximum length variables but make sure the column widths are at least as wide as their titles such as 'DriveLetter' or 'FileSystemType' etc.
    [System.Int64]$DriveLetterLength = 10
    [System.Int64]$FileSystemTypeLength = 13
    [System.Int64]$DriveTypeLength = 8
    [System.Int64]$SizeLength = 3

    # Loop through each element in the array
    foreach ($Drive in $AvailableRemovableDrives) {
        # Compare the length of the current element with the maximum length and update if needed
        if ($Drive.DriveLetter.Length -gt $DriveLetterLength) {
            $DriveLetterLength = $Drive.DriveLetter.Length
        }
        if ($Drive.FileSystemType.Length -gt $FileSystemTypeLength) {
            $FileSystemTypeLength = $Drive.FileSystemType.Length
        }
        if ($Drive.DriveType.Length -gt $DriveTypeLength) {
            $DriveTypeLength = $Drive.DriveType.Length
        }
        if (($Drive.Size | Measure-Object -Character).Characters -gt $SizeLength) {
            # The method below is used to calculate size of the string that consists only number, but since it now has "GB" in it, it's no longer needed
            # $SizeLength = ($Drive.Size | Measure-Object -Character).Characters
            $SizeLength = $Drive.Size.Length
        }
    }

    # Add 3 to each maximum length for spacing
    $DriveLetterLength += 3
    $FileSystemTypeLength += 3
    $DriveTypeLength += 3
    $SizeLength += 3

    # Creating a heading for the columns
    # Write the index of the drive
    Write-ColorfulText -C LavenderNoNewLine -I ('{0,-4}' -f '#')
    # Write the name of the drive
    Write-ColorfulText -C TeaGreenNoNewLine -I ("|{0,-$DriveLetterLength}" -f 'DriveLetter')
    # Write the File System Type of the drive
    Write-ColorfulText -C PinkNoNewLine -I ("|{0,-$FileSystemTypeLength}" -f 'FileSystemType')
    # Write the Drive Type of the drive
    Write-ColorfulText -C VioletNoNewLine -I ("|{0,-$DriveTypeLength}" -f 'DriveType')
    # Write the Size of the drive
    Write-ColorfulText -C Gold ("|{0,-$SizeLength}" -f 'Size')

    # Loop through the drives and display them in a table with colors
    for ($I = 0; $I -lt $AvailableRemovableDrives.Count; $I++) {
        # Write the index of the drive
        Write-ColorfulText -C LavenderNoNewLine -I ('{0,-4}' -f ($I + 1))
        # Write the name of the drive
        Write-ColorfulText -C TeaGreenNoNewLine -I ("|{0,-$DriveLetterLength}" -f $AvailableRemovableDrives[$I].DriveLetter)
        # Write the File System Type of the drive
        Write-ColorfulText -C PinkNoNewLine -I ("|{0,-$FileSystemTypeLength}" -f $AvailableRemovableDrives[$I].FileSystemType)
        # Write the Drive Type of the drive
        Write-ColorfulText -C VioletNoNewLine -I ("|{0,-$DriveTypeLength}" -f $AvailableRemovableDrives[$I].DriveType)
        # Write the Size of the drive
        Write-ColorfulText -C Gold ("|{0,-$SizeLength}" -f $AvailableRemovableDrives[$I].Size)
    }

    # Get the max count of available network drives and add 1 to it, assign the number as exit value to break the loop when selected
    [System.Int64]$ExitCodeRemovableDriveSelection = $AvailableRemovableDrives.Count + 1

    # Write an exit option at the end of the table
    Write-Host ('{0,-4}' -f "$ExitCodeRemovableDriveSelection") -NoNewline -ForegroundColor DarkRed
    Write-Host -Object '|Skip encryptions altogether' -ForegroundColor DarkRed

    function Confirm-Choice {
        <#
        .SYNOPSIS
            A function to validate the user input
        .INPUTS
            System.String
        .OUTPUTS
            System.Boolean
        #>
        param([System.String]$Choice)

        # Initialize a flag to indicate if the input is valid or not
        [System.Boolean]$IsValid = $false
        # Initialize a variable to store the parsed integer value
        [System.Int64]$ParsedChoice = 0
        # Try to parse the input as an integer
        # If the parsing succeeded, check if the input is within the range
        if ([System.Int64]::TryParse($Choice, [ref]$ParsedChoice)) {
            if ($ParsedChoice -in 1..$ExitCodeRemovableDriveSelection) {
                $IsValid = $true
                break
            }
        }
        # Return the flag value
        return $IsValid
    }

    # Prompt the user to enter the number of the drive they want to select, or exit value to exit, until they enter a valid input
    do {
        # Read the user input as a string
        [System.String]$Choice = $(Write-Host -Object "Enter the number of the drive you want to select or press $ExitCodeRemovableDriveSelection to Cancel" -ForegroundColor cyan; Read-Host)

        # Check if the input is valid using the Confirm-Choice function
        if (-NOT (Confirm-Choice -Choice $Choice)) {
            # Write an error message in red if invalid
            Write-Host -Object "Invalid input. Please enter a number between 1 and $ExitCodeRemovableDriveSelection." -ForegroundColor Red
        }
    } while (-NOT (Confirm-Choice -Choice $Choice))

    # Check if the user entered the exit value to break out of the loop
    if ($Choice -eq $ExitCodeRemovableDriveSelection) {
        break BitLockerCategoryLabel
    }
    else {
        # Get the selected drive from the array and display it
        return ($($AvailableRemovableDrives[$Choice - 1]).DriveLetter + ':')
    }
}
#Endregion Helper-Functions-And-ScriptBlocks

#Region Hardening-Categories-Functions
Function Invoke-MicrosoftSecurityBaselines {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🔐 Security Baselines'
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
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🧁 M365 Apps Security'
    :Microsoft365AppsSecurityBaselinesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Microsoft 365 Apps Security Baseline ?")) {
        'Yes' {
            [HardenWindowsSecurity.Microsoft365AppsSecurityBaselines]::Invoke()
        } 'No' { break Microsoft365AppsSecurityBaselinesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-MicrosoftDefender {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🍁 MSFT Defender'
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
                Write-Verbose -Message 'Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on'
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
                    Write-Verbose -Message 'Smart App Control is turned off, so Optional Diagnostic Data will not be enabled'
                }
            }

            Write-Verbose -Message 'Getting the state of fast weekly Microsoft recommended driver block list update scheduled task'
            [System.String]$BlockListScheduledTaskState = ([HardenWindowsSecurity.TaskSchedulerHelper]::Get('MSFT Driver Block list update', '\MSFT Driver Block list update\', 'TaskList')).State

            # Create scheduled task for fast weekly Microsoft recommended driver block list update if it doesn't exist or exists but is not Ready/Running
            if (($BlockListScheduledTaskState -notin '2', '3', '4')) {
                :TaskSchedulerCreationLabel switch ($RunUnattended ? ($MSFTDefender_NoScheduledTask ? 'No' : 'Yes') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nCreate scheduled task for fast weekly Microsoft recommended driver block list update ?")) {
                    'Yes' {
                        [HardenWindowsSecurity.MicrosoftDefender]::MSFTDefender_ScheduledTask()
                    } 'No' { break TaskSchedulerCreationLabel }
                    'Exit' { break MainSwitchLabel }
                }
            }
            else {
                Write-Verbose -Message "Scheduled task for fast weekly Microsoft recommended driver block list update already exists and is in $BlockListScheduledTaskState state"
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
                Write-Verbose -Message 'Microsoft Defender engine and platform update channel is already set to beta'
            }

        } 'No' { break MicrosoftDefenderLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-AttackSurfaceReductionRules {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🪷 ASR Rules'
    :ASRRulesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Attack Surface Reduction Rules category ?")) {
        'Yes' {
            [HardenWindowsSecurity.AttackSurfaceReductionRules]::Invoke()
        } 'No' { break ASRRulesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-BitLockerSettings {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🔑 BitLocker'
    # a ScriptBlock that gets the BitLocker recovery information for all drives that have a RecoveryPassword key protector
    [System.Management.Automation.ScriptBlock]$GetBitLockerRecoveryInfo = {
        Class BitLockerRecoveryInfo {
            [System.String]$DriveLetter
            [System.String]$Size
            [System.String]$KeyID
            [System.String]$RecoveryPassword
        }

        $BitLockerInfo = [System.Collections.Generic.List[BitLockerRecoveryInfo]]::new()

        Foreach ($Drive in Get-BitLockerVolume | Where-Object -FilterScript { 'RecoveryPassword' -in $_.KeyProtector.KeyProtectorType }) {

            # In case the drive has multiple recovery passwords
            [Microsoft.BitLocker.Structures.BitLockerVolumeKeyProtector[]]$RecoveryPasswordKeyProtectors = $Drive.KeyProtector | Where-Object -FilterScript { $_.KeyProtectorType -eq 'RecoveryPassword' }

            foreach ($RecoveryPassword in $RecoveryPasswordKeyProtectors) {

                $TempBitLockerRecoveryInfo = [BitLockerRecoveryInfo]::new()

                $TempBitLockerRecoveryInfo.DriveLetter = $Drive.MountPoint
                $TempBitLockerRecoveryInfo.Size = '{0:N4} GB' -f $Drive.CapacityGB
                $TempBitLockerRecoveryInfo.KeyID = $RecoveryPassword.KeyProtectorId
                $TempBitLockerRecoveryInfo.RecoveryPassword = $RecoveryPassword.RecoveryPassword

                [System.Void]$BitLockerInfo.Add($TempBitLockerRecoveryInfo)
            }
        }

        [System.String]$SavePath = "$env:SystemDrive\BitLocker-Recovery-Info-All-Drives.txt"

        Write-ColorfulText -Color Lavender -InputText "The Up-To-Date BitLocker recovery information of all drives have been saved to: $SavePath"

        $BitLockerInfo | Out-File -FilePath $SavePath -Force

        Add-Content -Path $SavePath -Value @'


Please refer to this page for additional assistance on BitLocker recovery:
https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview

'@
    }

    :BitLockerCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Bitlocker category ?")) {
        'Yes' {
            [HardenWindowsSecurity.BitLockerSettings]::Invoke()

            # Make sure there is no CD/DVD drives or mounted ISO in the system, because BitLocker throws an error when there is
            if ((Get-CimInstance -ClassName Win32_CDROMDrive -Property *).MediaLoaded) {
                Write-Warning -Message 'Remove any CD/DVD drives or mounted images/ISO from the system and run the Bitlocker category again.'
                # break from the entire BitLocker category and continue to the next category
                break BitLockerCategoryLabel
            }

            # check make sure Bitlocker isn't in the middle of decryption/encryption operation (on System Drive)
            if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -notin '100', '0') {
                $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
                Write-Host -Object "`nPlease wait for Bitlocker to finish encrypting or decrypting the Operation System Drive." -ForegroundColor Yellow
                Write-Host -Object "Drive $env:SystemDrive encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Yellow
                # break from the entire BitLocker category and continue to the next category
                break BitLockerCategoryLabel
            }

            :OSDriveEncryptionLabel switch ($RunUnattended ? 'Skip encryptions altogether' : (Select-Option -SubCategory -Options 'Normal: TPM + Startup PIN + Recovery Password', 'Enhanced: TPM + Startup PIN + Startup Key + Recovery Password', 'Backup the BitLocker recovery information of all drives' , 'Skip encryptions altogether', 'Exit' -Message "`nPlease select your desired security level" -ExtraMessage "If you are not sure, refer to the BitLocker category in the GitHub Readme`n")) {
                'Normal: TPM + Startup PIN + Recovery Password' {

                    # check if Bitlocker is enabled for the system drive with Normal security level
                    if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'on') {

                        # Get the OS Drive's encryption method
                        [System.String]$EncryptionMethodOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionMethod

                        # Check OS Drive's encryption method and display a warning if it's not the most secure one
                        if ($EncryptionMethodOSDrive -ine 'XtsAes256') {
                            Write-Warning -Message "The OS Drive is encrypted with the less secure '$EncryptionMethodOSDrive' encryption method instead of 'XtsAes256'"
                        }

                        # Get the key protectors of the OS Drive
                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                        # Get the key protector types of the OS Drive
                        [System.String[]]$KeyProtectorTypesOSDrive = $KeyProtectorsOSDrive.keyprotectortype

                        if ($KeyProtectorTypesOSDrive -contains 'TpmPinStartupKey' -and $KeyProtectorTypesOSDrive -contains 'recoveryPassword') {

                            switch (Select-Option -SubCategory -Options 'Yes', 'Skip OS Drive' , 'Exit' -Message "`nThe OS Drive is already encrypted with Enhanced Security level." -ExtraMessage "Are you sure you want to change it to Normal Security level?`n" ) {
                                'Skip OS Drive' { break OSDriveEncryptionLabel }
                                'Exit' { break MainSwitchLabel }
                            }
                        }

                        # check if TPM + PIN + recovery password are being used as key protectors for the OS Drive
                        if ($KeyProtectorTypesOSDrive -contains 'Tpmpin' -and $KeyProtectorTypesOSDrive -contains 'recoveryPassword') {

                            Write-ColorfulText -C MintGreen -I 'Bitlocker is already enabled for the OS drive with Normal security level.'
                        }
                        else {

                            # If the OS Drive doesn't have recovery password key protector
                            if ($KeyProtectorTypesOSDrive -notcontains 'recoveryPassword') {

                                Write-Host -Object "`nThe recovery password is missing, adding it now... `n" -ForegroundColor Yellow

                                # Add RecoveryPasswordProtector key protector to the OS drive
                                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                &$GetBitLockerRecoveryInfo
                            }

                            # If the OS Drive doesn't have (TPM + PIN) key protector
                            if ($KeyProtectorTypesOSDrive -notcontains 'Tpmpin') {

                                Write-Host -Object "`nTPM and Start up PIN are missing, adding them now..." -ForegroundColor Cyan

                                do {
                                    [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                    [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                    # Compare the PINs and make sure they match
                                    [System.Boolean]$TheyMatch = [HardenWindowsSecurity.SecureStringComparer]::Compare($Pin1, $Pin2)
                                    # If the PINs match and they are at least 10 characters long, max 20 characters
                                    if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                        [System.Security.SecureString]$Pin = $Pin1
                                    }
                                    else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                                }
                                # Repeat this process until the entered PINs match and they are at least 10 characters long, max 20 characters
                                until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                                try {
                                    # Add TPM + PIN key protectors to the OS Drive
                                    $null = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $Pin
                                    Write-ColorfulText -C MintGreen -I "`nPINs matched, enabling TPM and startup PIN now`n"
                                }
                                catch {
                                    Write-Host -Object 'These errors occurred, run Bitlocker category again after meeting the requirements' -ForegroundColor Red
                                    # Display errors in non-terminating way
                                    $_
                                    break BitLockerCategoryLabel
                                }

                                # Backup the recovery code of the OS drive in a file just in case - This is for when the disk is automatically encrypted and using TPM + Recovery code by default
                                &$GetBitLockerRecoveryInfo
                            }
                        }
                    }

                    # Do this if Bitlocker is not enabled for the OS drive at all
                    else {
                        Write-Host -Object "`nBitlocker is not enabled for the OS Drive, activating it now..." -ForegroundColor Yellow
                        do {
                            [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I 'Enter a Pin for Bitlocker startup (between 10 to 20 characters)'; Read-Host -AsSecureString)
                            [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                            [System.Boolean]$TheyMatch = [HardenWindowsSecurity.SecureStringComparer]::Compare($Pin1, $Pin2)

                            if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                [System.Security.SecureString]$Pin = $Pin1
                            }
                            else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                        }
                        until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                        try {
                            # Enable BitLocker for the OS Drive with TPM + PIN key protectors
                            Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod 'XtsAes256' -Pin $Pin -TpmAndPinProtector -SkipHardwareTest *> $null
                        }
                        catch {
                            Write-Host -Object 'These errors occurred, run Bitlocker category again after meeting the requirements' -ForegroundColor Red
                            $_
                            break BitLockerCategoryLabel
                        }
                        # Add recovery password key protector to the OS Drive
                        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                        $null = Resume-BitLocker -MountPoint $env:SystemDrive

                        &$GetBitLockerRecoveryInfo

                        Write-ColorfulText -C MintGreen -I "`nBitlocker is now enabled for the OS drive with Normal security level."
                    }

                }
                'Enhanced: TPM + Startup PIN + Startup Key + Recovery Password' {

                    # check if Bitlocker is enabled for the system drive with Enhanced security level
                    if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'on') {

                        # Get the OS Drive's encryption method
                        [System.String]$EncryptionMethodOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionMethod

                        # Check OS Drive's encryption method and display a warning if it's not the most secure one
                        if ($EncryptionMethodOSDrive -ine 'XtsAes256') {
                            Write-Warning -Message "The OS Drive is encrypted with the less secure '$EncryptionMethodOSDrive' encryption method instead of 'XtsAes256'"
                        }

                        # Get the key protectors of the OS Drive
                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector
                        # Get the key protector types of the OS Drive
                        [System.String[]]$KeyProtectorTypesOSDrive = $KeyProtectorsOSDrive.keyprotectortype

                        # check if TPM + PIN + recovery password are being used as key protectors for the OS Drive
                        if ($KeyProtectorTypesOSDrive -contains 'TpmPinStartupKey' -and $KeyProtectorTypesOSDrive -contains 'recoveryPassword') {

                            Write-ColorfulText -C MintGreen -I 'Bitlocker is already enabled for the OS drive with Enhanced security level.'
                        }
                        else {

                            # If the OS Drive doesn't have recovery password key protector
                            if ($KeyProtectorTypesOSDrive -notcontains 'recoveryPassword') {

                                Write-Host -Object "`nThe recovery password is missing, adding it now... `n" -ForegroundColor Yellow

                                # Add RecoveryPasswordProtector key protector to the OS drive
                                Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                &$GetBitLockerRecoveryInfo
                            }

                            # If the OS Drive doesn't have (TpmPinStartupKey) key protector
                            if ($KeyProtectorTypesOSDrive -notcontains 'TpmPinStartupKey') {

                                Write-ColorfulText -C Violet -I "`nTpm And Pin And StartupKey Protector is missing from the OS Drive, adding it now"

                                # Check if the OS drive has ExternalKey key protector and if it does remove it
                                # It's the standalone Startup Key protector which isn't secure on its own for the OS Drive
                                if ($KeyProtectorTypesOSDrive -contains 'ExternalKey') {

                                                    (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector |
                                    Where-Object -FilterScript { $_.keyprotectortype -eq 'ExternalKey' } |
                                    ForEach-Object -Process { $null = Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId }
                                }

                                do {
                                    [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                    [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                    # Compare the PINs and make sure they match
                                    [System.Boolean]$TheyMatch = [HardenWindowsSecurity.SecureStringComparer]::Compare($Pin1, $Pin2)
                                    # If the PINs match and they are at least 10 characters long, max 20 characters
                                    if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                        [System.Security.SecureString]$Pin = $Pin1
                                    }
                                    else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                                }
                                # Repeat this process until the entered PINs match and they are at least 10 characters long, max 20 characters
                                until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                                Write-ColorfulText -C MintGreen -I "`nPINs matched, enabling TPM, Startup PIN and Startup Key protector now`n"

                                try {
                                    # Add TpmAndPinAndStartupKeyProtector to the OS Drive
                                    $null = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinAndStartupKeyProtector -StartupKeyPath (Get-AvailableRemovableDrives) -Pin $Pin
                                }
                                catch {
                                    Write-Host -Object 'There was a problem adding Startup Key to the removable drive, try ejecting and reinserting the flash drive into your device and run this category again.' -ForegroundColor Red
                                    $_
                                    break BitLockerCategoryLabel
                                }

                                # Backup the recovery code of the OS drive in a file just in case - This is for when the disk is automatically encrypted and using TPM + Recovery code by default
                                &$GetBitLockerRecoveryInfo
                            }
                        }
                    }

                    # Do this if Bitlocker is not enabled for the OS drive at all
                    else {
                        Write-Host -Object "`nBitlocker is not enabled for the OS Drive, activating it now..." -ForegroundColor Yellow

                        do {
                            [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                            [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                            # Compare the PINs and make sure they match
                            [System.Boolean]$TheyMatch = [HardenWindowsSecurity.SecureStringComparer]::Compare($Pin1, $Pin2)
                            # If the PINs match and they are at least 10 characters long, max 20 characters
                            if ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) ) {
                                [System.Security.SecureString]$Pin = $Pin1
                            }
                            else { Write-Host -Object 'Please ensure that the PINs you entered match, and that they are between 10 to 20 characters.' -ForegroundColor red }
                        }
                        # Repeat this process until the entered PINs match and they are at least 10 characters long, max 20 characters
                        until ( $TheyMatch -and ($Pin1.Length -in 10..20) -and ($Pin2.Length -in 10..20) )

                        Write-ColorfulText -C MintGreen -I "`nPINs matched, enabling TPM, Startup PIN and Startup Key protector now`n"

                        try {
                            # Add TpmAndPinAndStartupKeyProtector to the OS Drive
                            Enable-BitLocker -MountPoint $env:SystemDrive -EncryptionMethod 'XtsAes256' -TpmAndPinAndStartupKeyProtector -StartupKeyPath (Get-AvailableRemovableDrives) -Pin $Pin -SkipHardwareTest *> $null
                        }
                        catch {
                            Write-Host -Object 'There was a problem adding Startup Key to the removable drive, try ejecting and reinserting the flash drive into your device and run this category again.' -ForegroundColor Red
                            $_
                            break BitLockerCategoryLabel
                        }

                        # Add recovery password key protector to the OS Drive
                        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                        $null = Resume-BitLocker -MountPoint $env:SystemDrive

                        &$GetBitLockerRecoveryInfo

                        Write-ColorfulText -C MintGreen -I "`nBitlocker is now enabled for the OS drive with Enhanced security level."
                    }
                }
                'Backup the BitLocker recovery information of all drives' {
                    &$GetBitLockerRecoveryInfo
                }
                'Skip encryptions altogether' { break BitLockerCategoryLabel } # Exit the entire BitLocker category, only
                'Exit' { break MainSwitchLabel }
            }

            # Setting Hibernate file size to full after making sure OS drive is property encrypted for holding hibernate data
            # Making sure the system is not a VM because Hibernate on VM doesn't work and VMs have other/better options than Hibernation
            if (-NOT (([HardenWindowsSecurity.GlobalVars]::MDAVConfigCurrent).IsVirtualMachine)) {

                # Check to see if Hibernate is already set to full and HiberFileType is set to 2 which is Full, 1 is Reduced
                try {
                    [System.Int64]$HiberFileType = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -ErrorAction SilentlyContinue
                }
                catch {
                    # Do nothing if the key doesn't exist
                }
                if ($HiberFileType -ne 2) {

                    $null = &"$env:SystemDrive\Windows\System32\powercfg.exe" /h /type full
                }
                else {
                    Write-ColorfulText -C Pink -I "`nHibernate is already set to full.`n"
                }
            }

            # If the function is running in unattended mode, skip the rest of the code in this function as they need user interaction
            if ($RunUnattended) { break BitLockerCategoryLabel }

            #region Non-OS-BitLocker-Drives-Detection

            # Get the list of non OS volumes
            [System.Object[]]$NonOSBitLockerVolumes = Get-BitLockerVolume |
            Where-Object -FilterScript { $_.volumeType -ne 'OperatingSystem' }

            # Get all the volumes and filter out removable ones
            [System.Object[]]$RemovableVolumes = Get-Volume | Where-Object -FilterScript { ($_.DriveType -eq 'Removable') -and $_.DriveLetter }

            # Check if there is any removable volumes
            if ($RemovableVolumes) {

                # Get the letters of all the removable volumes
                [System.String[]]$RemovableVolumesLetters = foreach ($RemovableVolume in $RemovableVolumes) {
                    $(($RemovableVolume).DriveLetter + ':' )
                }

                # Filter out removable drives from BitLocker volumes to process
                $NonOSBitLockerVolumes = $NonOSBitLockerVolumes |
                Where-Object -FilterScript { ($_.MountPoint -notin $RemovableVolumesLetters) }

            }
            #endregion Non-OS-BitLocker-Drives-Detection

            # if there is no non-OS volumes then skip the rest of the code in the BitLocker function
            if (!$NonOSBitLockerVolumes) { break BitLockerCategoryLabel }

            # Loop through each non-OS volume and prompt for encryption
            foreach ($MountPoint in $($NonOSBitLockerVolumes | Sort-Object).MountPoint) {

                # Prompt for confirmation before encrypting each drive
                switch (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEncrypt $MountPoint drive ?") {
                    'Yes' {

                        # Check if the non-OS drive that the user selected to be encrypted is not in the middle of any encryption/decryption operation
                        if ((Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -notin '100', '0') {
                            # Check if the drive isn't already encrypted and locked
                            if ((Get-BitLockerVolume -MountPoint $MountPoint).lockstatus -eq 'Locked') {
                                Write-Host -Object "`nThe drive $MountPoint is already encrypted and locked." -ForegroundColor Magenta
                                break
                            }
                            else {
                                $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage
                                Write-Host -Object "`nPlease wait for Bitlocker to finish encrypting or decrypting drive $MountPoint" -ForegroundColor Magenta
                                Write-Host -Object "Drive $MountPoint encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Magenta
                                break
                            }
                        }

                        # Check to see if Bitlocker is already turned on for the user selected drive
                        # if it is, perform multiple checks on its key protectors
                        if ((Get-BitLockerVolume -MountPoint $MountPoint).ProtectionStatus -eq 'on') {

                            # Get the OS Drive's encryption method
                            [System.String]$EncryptionMethodNonOSDrive = (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionMethod

                            # Check OS Drive's encryption method and display a warning if it's not the most secure one
                            if ($EncryptionMethodNonOSDrive -ine 'XtsAes256') {
                                Write-Warning -Message "Drive $MountPoint is encrypted with the less secure '$EncryptionMethodNonOSDrive' encryption method instead of 'XtsAes256'"
                            }

                            # Get the key protector types of the Non-OS Drive
                            [System.String[]]$KeyProtectorTypesNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector.keyprotectortype

                            # If Recovery Password and Auto Unlock key protectors are available on the drive
                            if ($KeyProtectorTypesNonOS -contains 'RecoveryPassword' -and $KeyProtectorTypesNonOS -contains 'ExternalKey') {

                                # Additional Check 1: if there are more than 1 ExternalKey key protector, try delete all of them and add a new one
                                # The external key protector that is being used to unlock the drive will not be deleted
                                                    ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                Where-Object -FilterScript { $_.keyprotectortype -eq 'ExternalKey' }).KeyProtectorId |
                                ForEach-Object -Process {
                                    # -ErrorAction SilentlyContinue makes sure no error is thrown if the drive only has 1 External key key protector
                                    # and it's being used to unlock the drive
                                    $null = Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue
                                }

                                # Renew the External key of the selected Non-OS Drive
                                $null = Enable-BitLockerAutoUnlock -MountPoint $MountPoint

                                # Additional Check 2: if there are more than 1 Recovery Password, delete all of them and add a new one
                                [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                    Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId

                                if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                    [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                    "Removing all of them and adding a new one. `n"
                                    Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                    # Remove all of the recovery password key protectors of the selected Non-OS Drive
                                    $RecoveryPasswordKeyProtectors | ForEach-Object -Process {
                                        $null = Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_
                                    }

                                    # Add a new Recovery Password key protector after removing all of the previous ones
                                    Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                    &$GetBitLockerRecoveryInfo
                                }
                                Write-ColorfulText -C MintGreen -I "`nBitlocker is already securely enabled for drive $MountPoint"
                            }

                            # If the selected drive has Auto Unlock key protector but doesn't have Recovery Password
                            elseif ($KeyProtectorTypesNonOS -contains 'ExternalKey' -and $KeyProtectorTypesNonOS -notcontains 'RecoveryPassword' ) {

                                # if there are more than 1 ExternalKey key protector, try delete all of them and add a new one
                                # The external key protector that is being used to unlock the drive will not be deleted
                                                    ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                Where-Object -FilterScript { $_.keyprotectortype -eq 'ExternalKey' }).KeyProtectorId |
                                ForEach-Object -Process {
                                    # -ErrorAction SilentlyContinue makes sure no error is thrown if the drive only has 1 External key key protector
                                    # and it's being used to unlock the drive
                                    $null = Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue
                                }

                                # Renew the External key of the selected Non-OS Drive
                                $null = Enable-BitLockerAutoUnlock -MountPoint $MountPoint

                                # Add Recovery Password Key protector and save it to a file inside the drive
                                Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                &$GetBitLockerRecoveryInfo

                                Write-Host -Object "`nDrive $MountPoint is auto-unlocked but doesn't have Recovery Password, adding it now... `n" -ForegroundColor Cyan
                            }

                            # Check 3: If the selected drive has Recovery Password key protector but doesn't have Auto Unlock enabled
                            elseif ($KeyProtectorTypesNonOS -contains 'RecoveryPassword' -and $KeyProtectorTypesNonOS -notcontains 'ExternalKey') {

                                # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                                $null = Enable-BitLockerAutoUnlock -MountPoint $MountPoint

                                # if there are more than 1 Recovery Password, delete all of them and add a new one
                                [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                    Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId

                                if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                    [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                    'Removing all of them and adding a new one.'
                                    Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                    # Delete all Recovery Passwords because there were more than 1
                                    $RecoveryPasswordKeyProtectors | ForEach-Object -Process {
                                        $null = Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_
                                    }

                                    # Add a new Recovery Password
                                    Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                    &$GetBitLockerRecoveryInfo
                                }
                            }
                        }

                        # Do this if Bitlocker isn't turned on at all on the user selected drive
                        else {
                            # Enable BitLocker with RecoveryPassword key protector for the selected Non-OS drive
                            Enable-BitLocker -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                            # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                            $null = Enable-BitLockerAutoUnlock -MountPoint $MountPoint

                            &$GetBitLockerRecoveryInfo

                            Write-ColorfulText -C MintGreen -I "`nBitLocker has started encrypting drive $MountPoint"
                        }
                    } 'No' { break }
                    'Exit' { break MainSwitchLabel }
                }
            }
        } 'No' { break BitLockerCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-TLSSecurity {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🛡️ TLS'
    :TLSSecurityLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun TLS Security category ?")) {
        'Yes' {
            [HardenWindowsSecurity.TLSSecurity]::Invoke()
        } 'No' { break TLSSecurityLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-LockScreen {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '💻 Lock Screen'
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
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '💎 UAC'
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
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🔥 Firewall'
    :WindowsFirewallLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Firewall category ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsFirewall]::Invoke()
        } 'No' { break WindowsFirewallLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-OptionalWindowsFeatures {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🏅 Optional Features'
    :OptionalFeaturesLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Optional Windows Features category ?")) {
        'Yes' {
            [HardenWindowsSecurity.OptionalWindowsFeatures]::Invoke()
        } 'No' { break OptionalFeaturesLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-WindowsNetworking {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '📶 Networking'
    :WindowsNetworkingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Networking category ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsNetworking]::Invoke()
        } 'No' { break WindowsNetworkingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-MiscellaneousConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🥌 Miscellaneous'
    :MiscellaneousLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Miscellaneous Configurations category ?")) {
        'Yes' {
            [HardenWindowsSecurity.MiscellaneousConfigurations]::Invoke()
        } 'No' { break MiscellaneousLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-WindowsUpdateConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🪟 Windows Update'
    :WindowsUpdateLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Windows Update Policies ?")) {
        'Yes' {
            [HardenWindowsSecurity.WindowsUpdateConfigurations]::Invoke()
        } 'No' { break WindowsUpdateLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-EdgeBrowserConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🦔 Edge'
    :MSEdgeLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Edge Browser Configurations ?")) {
        'Yes' {
            [HardenWindowsSecurity.EdgeBrowserConfigurations]::Invoke()
        } 'No' { break MSEdgeLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-CertificateCheckingCommands {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🎟️ Certificates'
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
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🧾 Country IPs'
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
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🎇 Downloads Defense Measures'
    :DownloadsDefenseMeasuresLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Downloads Defense Measures category ?")) {
        'Yes' {
            [HardenWindowsSecurity.DownloadsDefenseMeasures]::Invoke()
            :DangerousScriptHostsBlockingLabel switch ($RunUnattended ? ($DangerousScriptHostsBlocking ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Deploy the Dangerous Script Hosts Blocking WDAC Policy?')) {
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
    [HardenWindowsSecurity.GlobalVars]::Host.UI.RawUI.WindowTitle = '🏷️ Non-Admins'
    :NonAdminLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Non-Admin category ?")) {
        'Yes' {
            [HardenWindowsSecurity.NonAdminCommands]::Invoke()
            :ClipboardSyncLabel switch ($RunUnattended ? ($ClipboardSync ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Enable Clipboard Syncing with Microsoft Account')) {
                'Yes' {
                    [HardenWindowsSecurity.NonAdminCommands]::ClipboardSync()
                } 'No' { break ClipboardSyncLabel }
            }
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
