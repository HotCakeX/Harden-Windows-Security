#Requires -Version 7.4
Function Protect-WindowsSecurity {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]
        [ValidateSet(
            'WindowsBootManagerRevocations',
            'MicrosoftSecurityBaselines',
            'Microsoft365AppsSecurityBaselines',
            'MicrosoftDefender',
            'AttackSurfaceReductionRules',
            'BitLockerSettings',
            'TLSSecurity',
            'LockScreen',
            'UserAccountControl',
            'WindowsFirewall',
            'OptionalWindowsFeatures',
            'WindowsNetworking',
            'MiscellaneousConfigurations',
            'WindowsUpdateConfigurations',
            'EdgeBrowserConfigurations',
            'CertificateCheckingCommands',
            'CountryIPBlocking',
            'NonAdminCommands'
        )][System.String[]]$Categories
    )

    $ErrorActionPreference = 'Stop'

    $PSDefaultParameterValues = @{
        'Invoke-WebRequest:HttpVersion'    = '3.0'
        'Invoke-WebRequest:SslProtocol'    = 'Tls12,Tls13'
        'Invoke-RestMethod:HttpVersion'    = '3.0'
        'Invoke-RestMethod:SslProtocol'    = 'Tls12,Tls13'
        'Invoke-WebRequest:ProgressAction' = 'SilentlyContinue'
        'Invoke-RestMethod:ProgressAction' = 'SilentlyContinue'
        'Get-BitLockerVolume:ErrorAction'  = 'SilentlyContinue'
        'Get-CimInstance:Verbose'          = $false
        'Import-Module:Verbose'            = $false
    }

    # Determining whether to use the files inside the module or download them from the GitHub repository
    [System.Boolean]$IsLocally = $false
    if ($PSCommandPath) {
        if ((Split-Path -Path $PSCommandPath -Leaf) -eq 'Protect-WindowsSecurity.psm1') {
            Write-Verbose -Message 'Running Protect-WindowsSecurity function as part of the Harden-Windows-Security module'
            # Import functions
            . "$HardeningModulePath\Resources\Functions.ps1"
            [System.Boolean]$IsLocally = $true
        }
    }
    else {
        Write-Verbose -Message '$PSCommandPath was not found, Protect-WindowsSecurity function was most likely called from the GitHub repository'
    }

    # Determine whether the current session is running as Administrator or not
    [System.Security.Principal.WindowsIdentity]$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    [System.Security.Principal.WindowsPrincipal]$Principal = New-Object -TypeName 'Security.Principal.WindowsPrincipal' -ArgumentList $Identity
    [System.Boolean]$IsAdmin = $Principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) ? $True : $false

    # Get the execution policy for the current process
    [System.String]$CurrentExecutionPolicy = Get-ExecutionPolicy -Scope 'Process'

    # Change the execution policy temporarily only for the current PowerShell session
    Set-ExecutionPolicy -ExecutionPolicy 'Unrestricted' -Scope 'Process' -Force

    # Get the current title of the PowerShell
    [System.String]$CurrentPowerShellTitle = $Host.UI.RawUI.WindowTitle

    # Change the title of the Windows Terminal for PowerShell tab
    $Host.UI.RawUI.WindowTitle = '❤️‍🔥Harden Windows Security❤️‍🔥'

    # Minimum OS build number required for the hardening measures
    [System.Decimal]$Requiredbuild = '22621.2428'
    # Fetching Temp Directory
    [System.String]$CurrentUserTempDirectoryPath = [System.IO.Path]::GetTempPath()
    # The total number of the main categories for the parent/main progress bar to render
    [System.Int32]$TotalMainSteps = 18
    # Defining a boolean variable to determine whether optional diagnostic data should be enabled for Smart App Control or not
    [System.Boolean]$ShouldEnableOptionalDiagnosticData = $false

    #region Helper-Functions
    function Select-Option {
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
        return [System.String]$Selected
    }
    function Edit-Registry {
        <#
    .SYNOPSIS
        Function to modify registry
    .INPUTS
        System.String
    .OUTPUTS
        System.Void
    #>
        [CmdletBinding()]
        param ([System.String]$Path, [System.String]$Key, [System.String]$Value, [System.String]$Type, [System.String]$Action)
        If (-NOT (Test-Path -Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        if ($Action -eq 'AddOrModify') {
            New-ItemProperty -Path $Path -Name $Key -Value $Value -PropertyType $Type -Force | Out-Null
        }
        elseif ($Action -eq 'Delete') {
            Remove-ItemProperty -Path $Path -Name $Key -Force -ErrorAction SilentlyContinue | Out-Null
        }
    }
    function Compare-SecureString {
        <#
    .SYNOPSIS
        Safely compares two SecureString objects without decrypting them.
        Outputs $true if they are equal, or $false otherwise.
    .LINK
        https://stackoverflow.com/questions/48809012/compare-two-credentials-in-powershell
    .INPUTS
        System.Security.SecureString
    .OUTPUTS
        System.Boolean
    .PARAMETER SecureString1
        First secure string
    .PARAMETER SecureString2
        Second secure string to compare with the first secure string
    #>
        [CmdletBinding()]
        param(
            [System.Security.SecureString]$SecureString1,
            [System.Security.SecureString]$SecureString2
        )
        try {
            $Bstr1 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString1)
            $Bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString2)
            $Length1 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr1, -4)
            $Length2 = [Runtime.InteropServices.Marshal]::ReadInt32($Bstr2, -4)
            if ( $Length1 -ne $Length2 ) {
                return $false
            }
            for ( $I = 0; $I -lt $Length1; ++$I ) {
                $B1 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr1, $I)
                $B2 = [Runtime.InteropServices.Marshal]::ReadByte($Bstr2, $I)
                if ( $B1 -ne $B2 ) {
                    return $false
                }
            }
            return $true
        }
        finally {
            if ( $Bstr1 -ne [IntPtr]::Zero ) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr1)
            }
            if ( $Bstr2 -ne [IntPtr]::Zero ) {
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr2)
            }
        }
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

                [System.String]$Output = ''
                for ($I = 0; $I -lt $InputText.Length; $I++) {
                    $CurrentColor = $RainbowColors[$I % $RainbowColors.Length]
                    $Output += "$($PSStyle.Foreground.FromRGB($CurrentColor.R, $CurrentColor.G, $CurrentColor.B))$($PSStyle.Blink)$($InputText[$I])$($PSStyle.BlinkOff)$($PSStyle.Reset)"
                }
                Write-Output -InputObject $Output
                break
            }
            Default { Throw 'Unspecified Color' }
        }
    }
    function Get-AvailableRemovableDrives {
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
                New-Item -Path $Path -ItemType File -Value 'test' -Force | Out-Null
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
                                New-Item -Path $ExtremelyRandomPath -ItemType File -Value 'test' -Force | Out-Null
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
                    'Exit' { exit }
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
    function Block-CountryIP {
        <#
    .SYNOPSIS
        A function that gets a list of IP addresses and a name for them, then adds those IP addresses in the firewall block rules
    .NOTES
        -RemoteAddress in New-NetFirewallRule accepts array according to Microsoft Docs,
        so we use "[System.String[]]$IPList = $IPList -split '\r?\n' -ne ''" to convert the IP lists, which is a single multiline string, into an array

        how to query the number of IPs in each rule
        (Get-NetFirewallRule -DisplayName "OFAC Sanctioned Countries IP range blocking" -PolicyStore localhost | Get-NetFirewallAddressFilter).RemoteAddress.count
    .INPUTS
        System.String
        System.String[]
    .OUTPUTS
        System.Void
        #>
        [CmdletBinding()]
        param (
            [System.String[]]$IPList,
            [parameter(Mandatory = $True)][System.String]$ListName
        )
        
        # converts the list from string to string array
        [System.String[]]$IPList = $IPList -split '\r?\n' -ne ''

        # make sure the list isn't empty
        if ($IPList.count -ne 0) {
            # delete previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules
            Remove-NetFirewallRule -DisplayName "$ListName IP range blocking" -PolicyStore localhost -ErrorAction SilentlyContinue

            New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost
            New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost
        }
        else {
            Write-Warning -Message "The IP list was empty, skipping $ListName"
        }
    }
    function Edit-Addons {
        <#
        .SYNOPSIS
            A function to enable or disable Windows features and capabilities.
        .INPUTS
            System.String
        .OUTPUTS
            System.String
        #>
        [CmdletBinding()]
        param (
            [parameter(Mandatory = $true)]
            [ValidateSet('Capability', 'Feature')]
            [System.String]$Type,
            [parameter(Mandatory = $true, ParameterSetName = 'Capability')]
            [System.String]$CapabilityName,
            [parameter(Mandatory = $true, ParameterSetName = 'Feature')]
            [System.String]$FeatureName,
            [parameter(Mandatory = $true, ParameterSetName = 'Feature')]
            [ValidateSet('Enabling', 'Disabling')]
            [System.String]$FeatureAction
        )
        switch ($Type) {
            'Feature' {
                [System.String]$ActionCheck = ($FeatureAction -eq 'Enabling') ? 'disabled' : 'enabled'
                [System.String]$ActionOutput = ($FeatureAction -eq 'Enabling') ? 'enabled' : 'disabled'

                Write-ColorfulText -Color Lavender -InputText "`n$FeatureAction $FeatureName"
                if ((Get-WindowsOptionalFeature -Online -FeatureName $FeatureName).state -eq $ActionCheck) {
                    try {
                        if ($FeatureAction -eq 'Enabling') {
                            Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart | Out-Null
                        }
                        else {
                            Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart | Out-Null
                        }
                        # Shows the successful message only if the process was successful
                        Write-ColorfulText -Color NeonGreen -InputText "$FeatureName was successfully $ActionOutput"
                    }
                    catch {
                        # show errors in non-terminating way
                        $_
                    }
                }
                else {
                    Write-ColorfulText -Color NeonGreen -InputText "$FeatureName is already $ActionOutput"
                }
                break
            }
            'Capability' {
                Write-ColorfulText -Color Lavender -InputText "`nRemoving $CapabilityName"
                if ((Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CapabilityName*" }).state -ne 'NotPresent') {
                    try {
                        Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CapabilityName*" } | Remove-WindowsCapability -Online | Out-Null
                        # Shows the successful message only if the process was successful
                        Write-ColorfulText -Color NeonGreen -InputText "$CapabilityName was successfully removed."
                    }
                    catch {
                        # show errors in non-terminating way
                        $_
                    }
                }
                else {
                    Write-ColorfulText -Color NeonGreen -InputText "$CapabilityName is already removed."
                }
                break
            }
        }
    }
    #endregion Helper-Functions

    if ($IsAdmin) {
        # Get the current configurations and preferences of the Microsoft Defender
        [Microsoft.Management.Infrastructure.CimInstance]$MDAVConfigCurrent = Get-MpComputerStatus
        [Microsoft.Management.Infrastructure.CimInstance]$MDAVPreferencesCurrent = Get-MpPreference

        # backup the current allowed apps list in Controlled folder access in order to restore them at the end of the script
        # doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
        # no user customization will be affected
        [System.IO.FileInfo[]]$CFAAllowedAppsBackup = $MDAVPreferencesCurrent.ControlledFolderAccessAllowedApplications

        # Temporarily allow the currently running PowerShell executables to the Controlled Folder Access allowed apps
        # so that the script can run without interruption. This change is reverted at the end.
        # Adding powercfg.exe so Controlled Folder Access won't complain about it in BitLocker category when setting hibernate file size to full
        foreach ($FilePath in (((Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) + "$env:SystemDrive\Windows\System32\powercfg.exe")) {
            Add-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
        }
    }

    # doing a try-catch-finally block on the entire script so that when CTRL + C is pressed to forcefully exit the script,
    # or break is passed, clean up will still happen for secure exit. Any errors that happens will be thrown
    try {

        if (!$Categories) {
            Write-Host -Object "`r`n"
            Write-ColorfulText -Color Rainbow -InputText "############################################################################################################`r`n"
            Write-ColorfulText -Color MintGreen -InputText "### Please read the Readme in the GitHub repository: https://github.com/HotCakeX/Harden-Windows-Security ###`r`n"
            Write-ColorfulText -Color Rainbow -InputText "############################################################################################################`r`n"
        }

        #region RequirementsCheck
        # check if user's OS is Windows Home edition
        if ((Get-CimInstance -ClassName Win32_OperatingSystem).OperatingSystemSKU -eq '101') {
            Throw 'Windows Home edition detected, exiting...'
        }

        # check if user's OS is the latest build
        # Get OS build version
        [System.Decimal]$OSBuild = [System.Environment]::OSVersion.Version.Build
        # Get Update Build Revision (UBR) number
        [System.Decimal]$UBR = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
        # Create full OS build number as seen in Windows Settings
        [System.Decimal]$FullOSBuild = "$OSBuild.$UBR"

        # Make sure the current OS build is equal or greater than the required build
        if (-NOT ($FullOSBuild -ge $Requiredbuild)) {
            Throw "You're not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
        }

        if ($IsAdmin) {
            # check to make sure Secure Boot is enabled
            if (-NOT (Confirm-SecureBootUEFI)) {
                Throw 'Secure Boot is not enabled, please go to your UEFI settings to enable it and then try again.'
            }

            # check to make sure TPM is available and enabled
            [System.Object]$TPM = Get-Tpm
            if (-NOT ($TPM.tpmpresent -and $TPM.tpmenabled)) {
                Throw 'TPM is not available or enabled, please enable it in UEFI settings and try again.'
            }

            if (-NOT ($MDAVConfigCurrent.AMServiceEnabled -eq $true)) {
                Throw 'Microsoft Defender Anti Malware service is not enabled, please enable it and then try again.'
            }

            if (-NOT ($MDAVConfigCurrent.AntispywareEnabled -eq $true)) {
                Throw 'Microsoft Defender Anti Spyware is not enabled, please enable it and then try again.'
            }

            if (-NOT ($MDAVConfigCurrent.AntivirusEnabled -eq $true)) {
                Throw 'Microsoft Defender Anti Virus is not enabled, please enable it and then try again.'
            }

            if ($MDAVConfigCurrent.AMRunningMode -ne 'Normal') {
                Throw "Microsoft Defender is running in $($MDAVConfigCurrent.AMRunningMode) state, please remove any 3rd party AV and then try again."
            }
        }
        #endregion RequirementsCheck

        # Create the working directory
        [System.IO.DirectoryInfo]$WorkingDir = New-Item -ItemType Directory -Path "$CurrentUserTempDirectoryPath\HardeningXStuff\" -Force

        [System.Int64]$CurrentMainStep = 0
        Write-Progress -Id 0 -Activity 'Downloading the required files' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete 1
        # Change the title of the Windows Terminal for PowerShell tab
        $Host.UI.RawUI.WindowTitle = '⏬ Downloading'

        try {
            # Create an array of files to download
            [System.Object[]]$Files = @(
                # System.Net.WebClient requires absolute path instead of relative one
                @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Windows%2011%20v23H2%20Security%20Baseline.zip'; path = "$WorkingDir\MicrosoftSecurityBaseline.zip"; tag = 'MicrosoftSecurityBaseline' }
                @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/Microsoft%20365%20Apps%20for%20Enterprise%202306.zip'; path = "$WorkingDir\Microsoft365SecurityBaseline.zip"; tag = 'Microsoft365SecurityBaseline' }
                @{url = 'https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip'; path = "$WorkingDir\LGPO.zip"; tag = 'LGPO' }
                @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Security-Baselines-X.zip'; path = "$WorkingDir\Security-Baselines-X.zip"; tag = 'Security-Baselines-X' }
                @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/Registry.csv'; path = "$WorkingDir\Registry.csv"; tag = 'Registry' }
                @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/ProcessMitigations.csv'; path = "$WorkingDir\ProcessMitigations.csv"; tag = 'ProcessMitigations' }
                @{url = 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security%20Module/Main%20files/Resources/EventViewerCustomViews.zip'; path = "$WorkingDir\EventViewerCustomViews.zip"; tag = 'EventViewerCustomViews' }
            )

            # Get the total number of files to download based on whether the script is running locally or not
            [System.Int16]$TotalRequiredFiles = $IsLocally ? ($Files.Count - 4) : $Files.Count

            # Initialize a counter for the progress bar
            [System.Int16]$RequiredFilesCounter = 0

            # Start a job for each file download
            [System.Object[]]$Jobs = foreach ($File in $Files) {

                # If running locally, skip downloading the files that are already shipped with the Harden Windows Security module
                if ($IsLocally) {
                    if ($File.tag -in @('Security-Baselines-X', 'Registry', 'ProcessMitigations', 'EventViewerCustomViews')) {
                        Continue
                    }
                }

                Start-Job -ScriptBlock {

                    param([System.Uri]$Url, [System.IO.FileInfo]$Path, [System.String]$Tag)
                    # Create a WebClient object
                    [System.Net.WebClient]$WC = New-Object -TypeName System.Net.WebClient
                    try {
                        # Try to download the file from the original URL
                        $WC.DownloadFile($Url, $Path)
                    }
                    catch {
                        # a switch for when the original URLs are failing and to provide Alt URL
                        switch ($Tag) {
                            'Security-Baselines-X' {
                                Write-Host -Object 'Using Azure DevOps for Security-Baselines-X.zip' -ForegroundColor Yellow
                                [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Security-Baselines-X.zip'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            }
                            'Registry' {
                                Write-Host -Object 'Using Azure DevOps for Registry.csv' -ForegroundColor Yellow
                                [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/Registry.csv'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            }
                            'ProcessMitigations' {
                                Write-Host -Object 'Using Azure DevOps for ProcessMitigations.CSV' -ForegroundColor Yellow
                                [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/ProcessMitigations.csv'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            }
                            'EventViewerCustomViews' {
                                Write-Host -Object 'Using Azure DevOps for EventViewerCustomViews.zip' -ForegroundColor Yellow
                                [System.Uri]$AltURL = 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/Payload/EventViewerCustomViews.zip'
                                $WC.DownloadFile($AltURL, $Path)
                                break
                            }
                            default {
                                # Throw the error if any other URL fails and stop the operation
                                Throw $_
                            }
                        }
                    }
                } -ArgumentList $File.url, $File.path, $File.tag

                # Increment the counter by one
                $RequiredFilesCounter++

                # Write the progress of the download jobs
                Write-Progress -Id 1 -ParentId 0 -Activity "Downloading $($file.tag)" -Status "$RequiredFilesCounter of $TotalRequiredFiles" -PercentComplete ($RequiredFilesCounter / $TotalRequiredFiles * 100)
            }
            # Wait until all jobs are completed
            while ($Jobs | Where-Object -FilterScript { $_.State -ne 'Completed' }) {
                Start-Sleep -Milliseconds 700
            }

            # Receive the output or errors of each job and remove the job
            foreach ($Job in $Jobs) {
                Receive-Job -Job $Job
                Remove-Job -Job $Job
            }

            Write-Progress -Id 1 -ParentId 0 -Activity 'Downloading files completed.' -Completed
        }
        catch {
            foreach ($Job in $Jobs) { Remove-Job -Job $Job }
            Throw 'The required files could not be downloaded, Make sure you have Internet connection.'
        }

        # Copy the files that are shipped with the Harden Windows Security module to the working directory because they are not downloaded when running locally
        if ($IsLocally) {
            Copy-Item -Path "$HardeningModulePath\Resources\Security-Baselines-X.zip" -Destination "$WorkingDir\Security-Baselines-X.zip" -Force
            Copy-Item -Path "$HardeningModulePath\Resources\Registry.csv" -Destination "$WorkingDir\Registry.csv" -Force
            Copy-Item -Path "$HardeningModulePath\Resources\ProcessMitigations.csv" -Destination "$WorkingDir\ProcessMitigations.csv" -Force
            Copy-Item -Path "$HardeningModulePath\Resources\EventViewerCustomViews.zip" -Destination "$WorkingDir\EventViewerCustomViews.zip" -Force
        }

        # unzip Microsoft Security Baselines file
        Expand-Archive -Path "$WorkingDir\MicrosoftSecurityBaseline.zip" -DestinationPath "$WorkingDir\MicrosoftSecurityBaseline" -Force
        # unzip Microsoft 365 Apps Security Baselines file
        Expand-Archive -Path "$WorkingDir\Microsoft365SecurityBaseline.zip" -DestinationPath "$WorkingDir\Microsoft365SecurityBaseline" -Force
        # unzip the LGPO file
        Expand-Archive -Path "$WorkingDir\LGPO.zip" -DestinationPath "$WorkingDir\" -Force
        # unzip the Security-Baselines-X file which contains Windows Hardening script Group Policy Objects
        Expand-Archive -Path "$WorkingDir\Security-Baselines-X.zip" -DestinationPath "$WorkingDir\Security-Baselines-X\" -Force

        # capturing the Microsoft Security Baselines extracted path in a variable using wildcard and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
        [System.String]$MicrosoftSecurityBaselinePath = (Get-ChildItem -Directory -Path "$WorkingDir\MicrosoftSecurityBaseline\*\").FullName
        # capturing the Microsoft 365 Security Baselines extracted path in a variable using wildcard and storing it in a variable so that we won't need to change anything in the code other than the download link when they are updated
        [System.String]$Microsoft365SecurityBaselinePath = (Get-ChildItem -Directory -Path "$WorkingDir\Microsoft365SecurityBaseline\*\").FullName
        # Storing the registry CSV file in a variable
        [System.Object[]]$RegistryCSVItems = Import-Csv -Path "$WorkingDir\Registry.csv" -Delimiter ','
        # Storing the LGPO.exe path in a variable
        [System.IO.FileInfo]$LGPOExe = Get-ChildItem -Path "$WorkingDir\LGPO_30\LGPO.exe" -File

        # Copying LGPO.exe from its folder to Microsoft Security Baseline folder in order to get it ready to be used by PowerShell script
        Copy-Item -Path $LGPOExe -Destination "$MicrosoftSecurityBaselinePath\Scripts\Tools"
        # Copying LGPO.exe from its folder to Microsoft Office 365 Apps for Enterprise Security Baseline folder in order to get it ready to be used by PowerShell script
        Copy-Item -Path $LGPOExe -Destination "$Microsoft365SecurityBaselinePath\Scripts\Tools"

        #Region Hardening-Categories-Functions
        Function Invoke-WindowsBootManagerRevocations {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            # If admin rights are not detected, break out of the function
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🫶 Category 0'
            Write-Verbose -Message 'Running Category 0'

            :Category0Label switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply May 9 2023 Windows Boot Manager Security measures ? (If you've already run this category, don't need to do it again)")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Windows Boot Manager revocations for Secure Boot' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Secureboot /v AvailableUpdates /t REG_DWORD /d 0x30 /f

                    Write-Host -Object 'The required security measures have been applied to the system' -ForegroundColor Green
                    Write-Warning -Message 'Make sure to restart your device once. After restart, wait for at least 5-10 minutes and perform a 2nd restart to finish applying security measures completely.'
                } 'No' { break Category0Label }
                'Exit' { exit }
            }
        }
        Function Invoke-MicrosoftSecurityBaselines {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🔐 Security Baselines'
            Write-Verbose -Message 'Running Security Baselines category'
            Push-Location -Path "$MicrosoftSecurityBaselinePath\Scripts\"

            :MicrosoftSecurityBaselinesCategoryLabel switch ($RunUnattended ? 'Yes, With the Optional Overrides (Recommended)' :(Select-Option -Options 'Yes', 'Yes, With the Optional Overrides (Recommended)' , 'No', 'Exit' -Message "`nApply Microsoft Security Baseline ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Microsoft Security Baseline' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                    .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined
                }
                'Yes, With the Optional Overrides (Recommended)' {
                    Write-Progress -Id 0 -Activity 'Microsoft Security Baseline' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                    .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined

                    Start-Sleep -Seconds 1

                    # Apply the optional overrides
                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\GptTmpl.inf"

                    # Re-enables the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines
                    SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable
                }
                'No' { break MicrosoftSecurityBaselinesCategoryLabel }
                'Exit' { exit }
            }
            Pop-Location
        }
        Function Invoke-Microsoft365AppsSecurityBaselines {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🧁 M365 Apps Security'
            Write-Verbose -Message 'Running M365 Apps Security category'

            :Microsoft365AppsSecurityBaselinesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Microsoft 365 Apps Security Baseline ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Microsoft 365 Apps Security Baseline' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    Push-Location -Path "$Microsoft365SecurityBaselinePath\Scripts\"
                    # Run the official PowerShell script included in the Microsoft Security Baseline file we downloaded from Microsoft servers
                    .\Baseline-LocalInstall.ps1
                    Pop-Location

                } 'No' { break Microsoft365AppsSecurityBaselinesCategoryLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-MicrosoftDefender {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🍁 MSFT Defender'

            :MicrosoftDefenderLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Microsoft Defender category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Microsoft Defender' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\registry.pol"

                    # Optimizing Network Protection Performance of Windows Defender
                    Set-MpPreference -AllowSwitchToAsyncInspection $True

                    # Configure whether real-time protection and Security Intelligence Updates are enabled during OOBE
                    Set-MpPreference -OobeEnableRtpAndSigUpdate $True

                    # Enable Intel Threat Detection Technology
                    Set-MpPreference -IntelTDTEnabled $True

                    # Enable Restore point scan
                    Set-MpPreference -DisableRestorePoint $False

                    # Disable Performance mode of Defender that only applies to Dev drives by lowering security
                    Set-MpPreference -PerformanceModeStatus Disabled

                    # Network protection blocks network traffic instead of displaying a warning
                    Set-MpPreference -EnableConvertWarnToBlock $True

                    # Add OneDrive folders of all user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection
                    Get-ChildItem "$env:SystemDrive\Users\*\OneDrive*\" -Directory | ForEach-Object -Process { Add-MpPreference -ControlledFolderAccessProtectedFolders $_ }

                    # Enable Mandatory ASLR Exploit Protection system-wide
                    Set-ProcessMitigation -System -Enable ForceRelocateImages

                    # Apply Process Mitigations
                    [System.Object[]]$ProcessMitigations = Import-Csv -Path "$WorkingDir\ProcessMitigations.csv" -Delimiter ','

                    # Group the data by ProgramName
                    [System.Object[]]$GroupedMitigations = $ProcessMitigations | Group-Object -Property ProgramName
                    # Get the current process mitigations
                    [System.Object[]]$AllAvailableMitigations = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')

                    # Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
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

                    # Loop through each group to add the mitigations
                    foreach ($Group in $GroupedMitigations) {
                        # Get the program name
                        $ProgramName = $Group.Name

                        # Get the list of mitigations to enable
                        $EnableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Enable' } | Select-Object -ExpandProperty Mitigation

                        # Get the list of mitigations to disable
                        $DisableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Disable' } | Select-Object -ExpandProperty Mitigation

                        # Call the Set-ProcessMitigation cmdlet with the lists of mitigations
                        if ($null -ne $EnableMitigations) {
                            if ($null -ne $DisableMitigations) {
                                Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations -Disable $DisableMitigations
                            }
                            else {
                                Set-ProcessMitigation -Name $ProgramName -Enable $EnableMitigations
                            }
                        }
                        elseif ($null -ne $DisableMitigations) {
                            Set-ProcessMitigation -Name $ProgramName -Disable $DisableMitigations
                        }
                    }

                    # Turn on Data Execution Prevention (DEP) for all applications, including 32-bit programs
                    # Old method: bcdedit.exe /set '{current}' nx AlwaysOn | Out-Null
                    # New method using PowerShell cmdlets added in Windows 11
                    Set-BcdElement -Element 'nx' -Type 'Integer' -Value '3' -Force

                    # Suggest turning on Smart App Control only if it's in Eval mode
                    if ((Get-MpComputerStatus).SmartAppControlState -eq 'Eval') {
                        :SmartAppControlLabel switch ($RunUnattended ? 'No' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nTurn on Smart App Control ?")) {
                            'Yes' {
                                Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy' -key 'VerifiedAndReputablePolicyState' -value '1' -type 'DWORD' -Action 'AddOrModify'
                                # Let the optional diagnostic data be enabled automatically
                                $ShouldEnableOptionalDiagnosticData = $True
                            } 'No' { break SmartAppControlLabel }
                            'Exit' { exit }
                        }
                    }

                    # If Smart App Control is on or user selected to turn it on then automatically enable optional diagnostic data
                    if (($ShouldEnableOptionalDiagnosticData -eq $True) -or ((Get-MpComputerStatus).SmartAppControlState -eq 'On')) {
                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
                    }
                    else {
                        # Ask user if they want to turn on optional diagnostic data only if Smart App Control is not already turned off
                        if ((Get-MpComputerStatus).SmartAppControlState -ne 'Off') {
                            :SmartAppControlLabel2 switch ($RunUnattended ? 'Yes' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Optional Diagnostic Data ?" -ExtraMessage 'Required for Smart App Control usage and evaluation, read the GitHub Readme!')) {
                                'Yes' {
                                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
                                } 'No' { break SmartAppControlLabel2 }
                                'Exit' { exit }
                            }
                        }
                    }

                    # Get the state of fast weekly Microsoft recommended driver block list update scheduled task
                    [System.String]$BlockListScheduledTaskState = (Get-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath '\MSFT Driver Block list update\' -ErrorAction SilentlyContinue).State

                    # Create scheduled task for fast weekly Microsoft recommended driver block list update if it doesn't exist or exists but is not Ready/Running
                    if (-NOT (($BlockListScheduledTaskState -eq 'Ready' -or $BlockListScheduledTaskState -eq 'Running'))) {
                        :TaskSchedulerCreationLabel switch ($RunUnattended ? 'Yes' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nCreate scheduled task for fast weekly Microsoft recommended driver block list update ?")) {
                            'Yes' {
                                # Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
                                [Microsoft.Management.Infrastructure.CimInstance]$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                                    -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit 1};Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "$env:SystemDrive\Windows\System32\CodeIntegrity";citool --refresh -json;Remove-Item -Path .\VulnerableDriverBlockList -Recurse -Force;Remove-Item -Path .\VulnerableDriverBlockList.zip -Force; exit 0;}"'

                                # Create a scheduled task principal and assign the SYSTEM account's well-known SID to it so that the task will run under its context
                                [Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId 'S-1-5-18' -RunLevel Highest

                                # Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
                                [Microsoft.Management.Infrastructure.CimInstance]$Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)

                                # Register the scheduled task
                                Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update' -Force

                                # Define advanced settings for the scheduled task
                                [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8' -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 4 -RestartInterval (New-TimeSpan -Hours 6) -RunOnlyIfNetworkAvailable

                                # Add the advanced settings we defined above to the scheduled task
                                Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings
                            } 'No' { break TaskSchedulerCreationLabel }
                            'Exit' { exit }
                        }
                    }

                    # Only show this prompt if Engine and Platform update channels are not already set to Beta
                    if ( ($MDAVPreferencesCurrent.EngineUpdatesChannel -ne '2') -or ($MDAVPreferencesCurrent.PlatformUpdatesChannel -ne '2') ) {
                        # Set Microsoft Defender engine and platform update channel to beta - Devices in the Windows Insider Program are subscribed to this channel by default.
                        :DefenderUpdateChannelsLabel switch ($RunUnattended ? 'No' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nSet Microsoft Defender engine and platform update channel to beta ?")) {
                            'Yes' {
                                Set-MpPreference -EngineUpdatesChannel beta
                                Set-MpPreference -PlatformUpdatesChannel beta
                            } 'No' { break DefenderUpdateChannelsLabel }
                            'Exit' { exit }
                        }
                    }

                } 'No' { break MicrosoftDefenderLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-AttackSurfaceReductionRules {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🪷 ASR Rules'
            Write-Verbose -Message 'Running ASR Rules category'

            :ASRRulesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Attack Surface Reduction Rules category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Attack Surface Reduction Rules' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Attack Surface Reduction Rules Policies\registry.pol"
                } 'No' { break ASRRulesCategoryLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-BitLockerSettings {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🔑 BitLocker'
            Write-Verbose -Message 'Running BitLocker category'

            :BitLockerCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Bitlocker category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Bitlocker Settings' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Bitlocker Policies\registry.pol"

                    # This PowerShell script can be used to find out if the DMA Protection is ON \ OFF.
                    # The Script will show this by emitting True \ False for On \ Off respectively.

                    # bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
                    [System.String]$BootDMAProtectionCheck = @'
namespace SystemInfo
{
  using System;
  using System.Runtime.InteropServices;

  public static class NativeMethods
  {
    internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
    {
      /// </summary>
      SystemDmaGuardPolicyInformation = 202
    }

    [DllImport("ntdll.dll")]
    internal static extern Int32 NtQuerySystemInformation(
      SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
      IntPtr SystemInformation,
      Int32 SystemInformationLength,
      out Int32 ReturnLength);

    public static byte BootDmaCheck()
    {
      Int32 result;
      Int32 SystemInformationLength = 1;
      IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
      Int32 ReturnLength;

      result = NativeMethods.NtQuerySystemInformation(
                NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                SystemInformation,
                SystemInformationLength,
                out ReturnLength);

      if (result == 0)
      {
        byte info = Marshal.ReadByte(SystemInformation, 0);
        return info;
      }

      return 0;
    }
  }
}
'@
                    # if the type is not already loaded, load it
                    if (-NOT ('SystemInfo.NativeMethods' -as [System.Type])) {
                        Write-Verbose -Message 'Loading SystemInfo.NativeMethods type'
                        Add-Type -TypeDefinition $BootDMAProtectionCheck -Language CSharp -Verbose:$false
                    }
                    else {
                        Write-Verbose -Message 'SystemInfo.NativeMethods type is already loaded, skipping loading it again.'
                    }

                    # returns true or false depending on whether Kernel DMA Protection is on or off
                    [System.Boolean]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

                    # Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
                    if ($BootDMAProtection) {
                        Write-Host -Object 'Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.' -ForegroundColor Blue
                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure OFF\Registry.pol"
                    }
                    else {
                        Write-Host -Object 'Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.' -ForegroundColor Blue
                        &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure ON\Registry.pol"
                    }

                    # Set-up Bitlocker encryption for OS Drive with TPMandPIN and recovery password keyprotectors and Verify its implementation
                    # check, make sure there is no CD/DVD drives in the system, because Bitlocker throws an error when there is
                    if ((Get-CimInstance -ClassName Win32_CDROMDrive -Property *).MediaLoaded) {
                        Write-Warning -Message 'Remove any CD/DVD drives or mounted images/ISO from the system and run the Bitlocker category again.'
                        # break from the entire BitLocker category and continue to the next category
                        break BitLockerCategoryLabel
                    }

                    # check make sure Bitlocker isn't in the middle of decryption/encryption operation (on System Drive)
                    if ((Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne '100' -and (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage -ne '0') {
                        $EncryptionPercentageVar = (Get-BitLockerVolume -MountPoint $env:SystemDrive).EncryptionPercentage
                        Write-Host -Object "`nPlease wait for Bitlocker to finish encrypting or decrypting the Operation System Drive." -ForegroundColor Yellow
                        Write-Host -Object "Drive $env:SystemDrive encryption is currently at $EncryptionPercentageVar percent." -ForegroundColor Yellow
                        # break from the entire BitLocker category and continue to the next category
                        break BitLockerCategoryLabel
                    }

                    # A script block that generates recovery code just like the Windows does
                    [System.Management.Automation.ScriptBlock]$RecoveryPasswordContentGenerator = {
                        param ([System.Object[]]$KeyProtectorsInputFromScriptBlock)

                        return @"
    BitLocker Drive Encryption recovery key

    To verify that this is the correct recovery key, compare the start of the following identifier with the identifier value displayed on your PC.

    Identifier:

            $(($KeyProtectorsInputFromScriptBlock | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId.Trim('{', '}'))

    If the above identifier matches the one displayed by your PC, then use the following key to unlock your drive.

    Recovery Key:

            $(($KeyProtectorsInputFromScriptBlock | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)

    If the above identifier doesn't match the one displayed by your PC, then this isn't the right key to unlock your drive.
    Try another recovery key, or refer to https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview for additional assistance.

    IMPORTANT: Make sure to keep it in a safe place, e.g., in OneDrive's Personal Vault which requires additional authentication to access.

"@
                    }

                    :OSDriveEncryptionLabel switch ($RunUnattended ? 'Skip encryptions altogether' : (Select-Option -SubCategory -Options 'Normal: TPM + Startup PIN + Recovery Password', 'Enhanced: TPM + Startup PIN + Startup Key + Recovery Password', 'Skip encryptions altogether', 'Exit' -Message "`nPlease select your desired security level" -ExtraMessage "If you are not sure, refer to the BitLocker category in the GitHub Readme`n")) {
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
                                        'Exit' { exit }
                                    }
                                }

                                # check if TPM + PIN + recovery password are being used as key protectors for the OS Drive
                                if ($KeyProtectorTypesOSDrive -contains 'Tpmpin' -and $KeyProtectorTypesOSDrive -contains 'recoveryPassword') {

                                    Write-ColorfulText -C MintGreen -I 'Bitlocker is already enabled for the OS drive with Normal security level.'

                                    Write-ColorfulText -C Fuchsia -I 'Here is your 48-digits recovery password for the OS drive in case you were looking for it:'
                                    Write-ColorfulText -C Rainbow -I "$(($KeyProtectorsOSDrive | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
                                }
                                else {

                                    # If the OS Drive doesn't have recovery password key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'recoveryPassword') {

                                        [System.String]$BitLockerMsg = "`nThe recovery password is missing, adding it now... `n" +
                                        "It will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'"
                                        Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                        # Add RecoveryPasswordProtector key protector to the OS drive
                                        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                        # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null
                                    }

                                    # If the OS Drive doesn't have (TPM + PIN) key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'Tpmpin') {

                                        Write-Host -Object "`nTPM and Start up PIN are missing, adding them now..." -ForegroundColor Cyan

                                        do {
                                            [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                            [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                            # Compare the PINs and make sure they match
                                            [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2
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
                                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinProtector -Pin $Pin | Out-Null
                                            Write-ColorfulText -C MintGreen -I "`nPINs matched, enabling TPM and startup PIN now`n"
                                        }
                                        catch {
                                            Write-Host -Object 'These errors occurred, run Bitlocker category again after meeting the requirements' -ForegroundColor Red
                                            $_
                                            break BitLockerCategoryLabel
                                        }

                                        # Get the key protectors of the OS Drive
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file just in case - This is for when the disk is automatically encrypted and using TPM + Recovery code by default
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                        Write-Host -Object "The recovery password was backed up in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan
                                    }
                                }
                            }

                            # Do this if Bitlocker is not enabled for the OS drive at all
                            else {
                                Write-Host -Object "`nBitlocker is not enabled for the OS Drive, activating it now..." -ForegroundColor Yellow
                                do {
                                    [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I 'Enter a Pin for Bitlocker startup (between 10 to 20 characters)'; Read-Host -AsSecureString)
                                    [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                    [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2

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

                                # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                # Backup the recovery code of the OS drive in a file
                                New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null

                                Write-ColorfulText -C MintGreen -I "`nBitlocker is now enabled for the OS drive with Normal security level."
                                Write-Host -Object "The recovery password will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan
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

                                    Write-ColorfulText -C Fuchsia -I 'Here is your 48-digits recovery password for the OS drive in case you were looking for it:'
                                    Write-ColorfulText -C Rainbow -I "$(($KeyProtectorsOSDrive | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
                                }
                                else {

                                    # If the OS Drive doesn't have recovery password key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'recoveryPassword') {

                                        [System.String]$BitLockerMsg = "`nThe recovery password is missing, adding it now... `n" +
                                        "It will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'"
                                        Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                        # Add RecoveryPasswordProtector key protector to the OS drive
                                        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector *> $null

                                        # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                    }

                                    # If the OS Drive doesn't have (TpmPinStartupKey) key protector
                                    if ($KeyProtectorTypesOSDrive -notcontains 'TpmPinStartupKey') {

                                        Write-ColorfulText -C Violet -I "`nTpm And Pin And StartupKey Protector is missing from the OS Drive, adding it now"

                                        # Check if the OS drive has ExternalKey key protector and if it does remove it
                                        # It's the standalone Startup Key protector which isn't secure on its own for the OS Drive
                                        if ($KeyProtectorTypesOSDrive -contains 'ExternalKey') {

                                            (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector |
                                            Where-Object -FilterScript { $_.keyprotectortype -eq 'ExternalKey' } |
                                            ForEach-Object -Process { Remove-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $_.KeyProtectorId | Out-Null }
                                        }

                                        do {
                                            [System.Security.SecureString]$Pin1 = $(Write-ColorfulText -C PinkBold -I "`nEnter a Pin for Bitlocker startup (between 10 to 20 characters)"; Read-Host -AsSecureString)
                                            [System.Security.SecureString]$Pin2 = $(Write-ColorfulText -C PinkBold -I 'Confirm your Bitlocker Startup Pin (between 10 to 20 characters)'; Read-Host -AsSecureString)

                                            # Compare the PINs and make sure they match
                                            [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2
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
                                            Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmAndPinAndStartupKeyProtector -StartupKeyPath (Get-AvailableRemovableDrives) -Pin $Pin | Out-Null
                                        }
                                        catch {
                                            Write-Host -Object 'There was a problem adding Startup Key to the removable drive, try ejecting and reinserting the flash drive into your device and run this category again.' -ForegroundColor Red
                                            $_
                                            break BitLockerCategoryLabel
                                        }

                                        # Get the key protectors of the OS Drive
                                        [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                        # Backup the recovery code of the OS drive in a file just in case - This is for when the disk is automatically encrypted and using TPM + Recovery code by default
                                        New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                        Write-Host -Object "The recovery password was backed up in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan

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
                                    [System.Boolean]$TheyMatch = Compare-SecureString -SecureString1 $Pin1 -SecureString2 $Pin2
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

                                # Get the new key protectors of the OS Drive after adding RecoveryPasswordProtector to it
                                [System.Object[]]$KeyProtectorsOSDrive = (Get-BitLockerVolume -MountPoint $env:SystemDrive).KeyProtector

                                # Backup the recovery code of the OS drive in a file
                                New-Item -Path "$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsOSDrive) -ItemType File -Force | Out-Null

                                Resume-BitLocker -MountPoint $env:SystemDrive | Out-Null

                                Write-ColorfulText -C MintGreen -I "`nBitlocker is now enabled for the OS drive with Enhanced security level."
                                Write-Host -Object "The recovery password will be saved in a text file in '$env:SystemDrive\Drive $($env:SystemDrive.remove(1)) recovery password.txt'" -ForegroundColor Cyan
                            }
                        }
                        'Skip encryptions altogether' { break BitLockerCategoryLabel } # Exit the entire BitLocker category, only
                        'Exit' { exit }
                    }

                    # Setting Hibernate file size to full after making sure OS drive is property encrypted for holding hibernate data
                    # Making sure the system is not a VM because Hibernate on VM doesn't work and VMs have other/better options than Hibernation
                    if (-NOT ((Get-MpComputerStatus).IsVirtualMachine)) {

                        # Check to see if Hibernate is already set to full and HiberFileType is set to 2 which is Full, 1 is Reduced
                        try {
                            [System.Int64]$HiberFileType = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -ErrorAction SilentlyContinue
                        }
                        catch {
                            # Do nothing if the key doesn't exist
                        }
                        if ($HiberFileType -ne 2) {

                            Write-Progress -Id 6 -ParentId 0 -Activity 'Hibernate' -Status 'Setting Hibernate file size to full' -PercentComplete 50

                            # Set Hibernate mode to full
                            &"$env:SystemDrive\Windows\System32\powercfg.exe" /h /type full | Out-Null

                            Write-Progress -Id 6 -Activity 'Setting Hibernate file size to full' -Completed
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
                                if ((Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne '100' -and (Get-BitLockerVolume -MountPoint $MountPoint).EncryptionPercentage -ne '0') {
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
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue | Out-Null
                                        }

                                        # Renew the External key of the selected Non-OS Drive
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                        # Additional Check 2: if there are more than 1 Recovery Password, delete all of them and add a new one
                                        [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId

                                        if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                            [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                            "Removing all of them and adding a new one. `n" +
                                            "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                            Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                            # Remove all of the recovery password key protectors of the selected Non-OS Drive
                                            $RecoveryPasswordKeyProtectors | ForEach-Object -Process {
                                                Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ | Out-Null
                                            }

                                            # Add a new Recovery Password key protector after removing all of the previous ones
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                            # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                            [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                            # Backup the recovery code of the Non-OS drive in a file
                                            New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null

                                        }
                                        Write-ColorfulText -C MintGreen -I "`nBitlocker is already securely enabled for drive $MountPoint"

                                        # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                        # Just to simply display it on the console for the user
                                        [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                        Write-ColorfulText -C Fuchsia -I "Here is your 48-digits recovery password for drive $MountPoint in case you were looking for it:"
                                        Write-ColorfulText -C Rainbow -I "$(($KeyProtectorsNonOS | Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).RecoveryPassword)"
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
                                            Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ -ErrorAction SilentlyContinue | Out-Null
                                        }

                                        # Renew the External key of the selected Non-OS Drive
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                        # Add Recovery Password Key protector and save it to a file inside the drive
                                        Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                        # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                        [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                        # Backup the recovery code of the Non-OS drive in a file
                                        New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null

                                        [System.String]$BitLockerMsg = "`nDrive $MountPoint is auto-unlocked but doesn't have Recovery Password, adding it now... `n" +
                                        "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                        Write-Host -Object $BitLockerMsg -ForegroundColor Cyan
                                    }

                                    # Check 3: If the selected drive has Recovery Password key protector but doesn't have Auto Unlock enabled
                                    elseif ($KeyProtectorTypesNonOS -contains 'RecoveryPassword' -and $KeyProtectorTypesNonOS -notcontains 'ExternalKey') {

                                        # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                                        Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                        # if there are more than 1 Recovery Password, delete all of them and add a new one
                                        [System.String[]]$RecoveryPasswordKeyProtectors = ((Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector |
                                            Where-Object -FilterScript { $_.keyprotectortype -eq 'RecoveryPassword' }).KeyProtectorId

                                        if ($RecoveryPasswordKeyProtectors.Count -gt 1) {

                                            [System.String]$BitLockerMsg = "`nThere are more than 1 recovery password key protector associated with the drive $mountpoint `n" +
                                            'Removing all of them and adding a new one.' +
                                            "It will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'"
                                            Write-Host -Object $BitLockerMsg -ForegroundColor Yellow

                                            # Delete all Recovery Passwords because there were more than 1
                                            $RecoveryPasswordKeyProtectors | ForEach-Object -Process {
                                                Remove-BitLockerKeyProtector -MountPoint $MountPoint -KeyProtectorId $_ | Out-Null
                                            }

                                            # Add a new Recovery Password
                                            Add-BitLockerKeyProtector -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                            # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                            [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                            # Backup the recovery code of the Non-OS drive in a file
                                            New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null
                                        }
                                    }
                                }

                                # Do this if Bitlocker isn't turned on at all on the user selected drive
                                else {
                                    # Enable BitLocker with RecoveryPassword key protector for the selected Non-OS drive
                                    Enable-BitLocker -MountPoint $MountPoint -RecoveryPasswordProtector *> $null

                                    # Add Auto-unlock (a.k.a ExternalKey key protector to the drive)
                                    Enable-BitLockerAutoUnlock -MountPoint $MountPoint | Out-Null

                                    # Get the new key protectors of the Non-OS Drive after adding RecoveryPasswordProtector to it
                                    [System.Object[]]$KeyProtectorsNonOS = (Get-BitLockerVolume -MountPoint $MountPoint).KeyProtector

                                    # Backup the recovery code of the Non-OS drive in a file
                                    New-Item -Path "$MountPoint\Drive $($MountPoint.Remove(1)) recovery password.txt" -Value $(&$RecoveryPasswordContentGenerator $KeyProtectorsNonOS) -ItemType File -Force | Out-Null

                                    Write-ColorfulText -C MintGreen -I "`nBitLocker has started encrypting drive $MountPoint"
                                    Write-Host -Object "Recovery password will be saved in a text file in '$($MountPoint)\Drive $($MountPoint.Remove(1)) recovery password.txt'" -ForegroundColor Cyan
                                }
                            } 'No' { break }
                            'Exit' { exit }
                        }
                    }
                } 'No' { break BitLockerCategoryLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-TLSSecurity {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🛡️ TLS'
            Write-Verbose -Message 'Running TLS Security category'

            :TLSSecurityLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun TLS Security category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'TLS Security' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    # creating these registry keys that have forward slashes in them
                    @(  'DES 56/56', # DES 56-bit
                        'RC2 40/128', # RC2 40-bit
                        'RC2 56/128', # RC2 56-bit
                        'RC2 128/128', # RC2 128-bit
                        'RC4 40/128', # RC4 40-bit
                        'RC4 56/128', # RC4 56-bit
                        'RC4 64/128', # RC4 64-bit
                        'RC4 128/128', # RC4 128-bit
                        'Triple DES 168' # 3DES 168-bit (Triple DES 168)
                    ) | ForEach-Object -Process {
                        [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$_") | Out-Null
                    }

                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'TLS') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\TLS Security\registry.pol"
                } 'No' { break TLSSecurityLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-LockScreen {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '💻 Lock Screen'
            Write-Verbose -Message 'Running Lock Screen category'

            :LockScreenLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Lock Screen category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Lock Screen' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Lock Screen Policies\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\GptTmpl.inf"

                    # Apply the Don't display last signed-in policy
                    :LockScreenLastSignedInLabel switch ($RunUnattended ? 'No' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nDon't display last signed-in on logon screen ?" -ExtraMessage 'Read the GitHub Readme!')) {
                        'Yes' {
                            Write-Progress -Id 2 -ParentId 0 -Activity 'Lock Screen' -Status "Applying the Don't display last signed-in policy" -PercentComplete 50

                            &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\Don't display last signed-in\GptTmpl.inf"

                            Write-Progress -Id 2 -Activity "Applying the Don't display last signed-in policy" -Completed
                        } 'No' { break LockScreenLastSignedInLabel }
                        'Exit' { exit }
                    }

                    # Enable CTRL + ALT + DEL
                    :CtrlAltDelLabel switch ($RunUnattended ? 'No' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable requiring CTRL + ALT + DEL on lock screen ?")) {
                        'Yes' {
                            Write-Progress -Id 3 -ParentId 0 -Activity 'Lock Screen' -Status "Applying the Don't display last signed-in policy" -PercentComplete 50

                            &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Lock Screen Policies\Enable CTRL + ALT + DEL\GptTmpl.inf"

                            Write-Progress -Id 3 -Activity "Applying the Don't display last signed-in policy" -Completed
                        } 'No' { break CtrlAltDelLabel }
                        'Exit' { exit }
                    }
                } 'No' { break LockScreenLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-UserAccountControl {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '💎 UAC'
            Write-Verbose -Message 'Running User Account Control category'

            :UACLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun User Account Control category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'User Account Control' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\GptTmpl.inf"

                    # Apply the Hide the entry points for Fast User Switching policy
                    :FastUserSwitchingLabel switch ($RunUnattended ? 'No' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nHide the entry points for Fast User Switching ?" -ExtraMessage 'Read the GitHub Readme!')) {
                        'Yes' {
                            Write-Progress -Id 4 -ParentId 0 -Activity 'User Account Control' -Status 'Hide the entry points for Fast User Switching policy' -PercentComplete 50

                            &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\Hides the entry points for Fast User Switching\registry.pol"

                            Write-Progress -Id 4 -Activity 'Hide the entry points for Fast User Switching policy' -Completed
                        } 'No' { break FastUserSwitchingLabel }
                        'Exit' { exit }
                    }

                    # Apply the Only elevate executables that are signed and validated policy
                    :ElevateSignedExeLabel switch ($RunUnattended ? 'No' : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nOnly elevate executables that are signed and validated ?" -ExtraMessage 'Read the GitHub Readme!')) {
                        'Yes' {
                            Write-Progress -Id 5 -ParentId 0 -Activity 'User Account Control' -Status 'Only elevate executables that are signed and validated' -PercentComplete 50

                            &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\User Account Control UAC Policies\Only elevate executables that are signed and validated\GptTmpl.inf"

                            Write-Progress -Id 5 -Activity 'Only elevate executables that are signed and validated' -Completed
                        } 'No' { break ElevateSignedExeLabel }
                        'Exit' { exit }
                    }
                } 'No' { break UACLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-WindowsFirewall {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🔥 Firewall'
            Write-Verbose -Message 'Running Windows Firewall category'

            :WindowsFirewallLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Firewall category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Windows Firewall' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Firewall Policies\registry.pol"

                    # Disables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules
                    Get-NetFirewallRule |
                    Where-Object -FilterScript { $_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302' -and $_.Direction -eq 'inbound' } |
                    ForEach-Object -Process { Disable-NetFirewallRule -DisplayName $_.DisplayName }
                } 'No' { break WindowsFirewallLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-OptionalWindowsFeatures {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🏅 Optional Features'
            Write-Verbose -Message 'Running Optional Windows Features category'

            :OptionalFeaturesLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Optional Windows Features category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Optional Windows Features' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    # PowerShell Core (only if installed from Microsoft Store) has problem with these commands: https://github.com/PowerShell/PowerShell/issues/13866#issuecomment-1519066710
                    # Windows Powershell (old one) doesn't support the -UseWindowsPowerShell parameter, so only performing the import if PS Core is installed from Microsoft Store
                    if (($PSHome -like "*$env:SystemDrive\Program Files\WindowsApps\Microsoft.PowerShell*") -and ($PSVersionTable.PSEdition -eq 'Core')) {
                        Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
                    }

                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2Root'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'WorkFolders-Client'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Printing-Foundation-Features'
                    Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Windows-Defender-ApplicationGuard'
                    Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Containers-DisposableClientVM'
                    Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Microsoft-Hyper-V'
                    Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'VirtualMachinePlatform'
                    Edit-Addons -Type Capability -CapabilityName 'Media.WindowsMediaPlayer'
                    Edit-Addons -Type Capability -CapabilityName 'Browser.InternetExplorer'
                    Edit-Addons -Type Capability -CapabilityName 'wmic'
                    Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.Notepad.System'
                    Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.WordPad'
                    Edit-Addons -Type Capability -CapabilityName 'Microsoft.Windows.PowerShell.ISE'
                    Edit-Addons -Type Capability -CapabilityName 'App.StepsRecorder'

                    # Uninstall VBScript that is now uninstallable as an optional features since Windows 11 insider Dev build 25309 - Won't do anything in other builds
                    if (Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*VBSCRIPT*' }) {
                        try {
                            Write-ColorfulText -Color Lavender -InputText "`nUninstalling VBSCRIPT"
                            Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like '*VBSCRIPT*' } | Remove-WindowsCapability -Online
                            # Shows the successful message only if removal process was successful
                            Write-ColorfulText -Color NeonGreen -InputText 'VBSCRIPT has been uninstalled'
                        }
                        catch {
                            # show errors in non-terminating way
                            $_
                        }
                    }
                } 'No' { break OptionalFeaturesLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-WindowsNetworking {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '📶 Networking'
            Write-Verbose -Message 'Running Windows Networking category'

            :WindowsNetworkingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Networking category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Windows Networking' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Networking Policies\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Windows Networking Policies\GptTmpl.inf"

                    # Disable LMHOSTS lookup protocol on all network adapters
                    Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -key 'EnableLMHOSTS' -value '0' -type 'DWORD' -Action 'AddOrModify'

                    # Set the Network Location of all connections to Public
                    Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
                } 'No' { break WindowsNetworkingLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-MiscellaneousConfigurations {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🥌 Miscellaneous'
            Write-Verbose -Message 'Running Miscellaneous Configurations category'

            :MiscellaneousLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Miscellaneous Configurations category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Miscellaneous Configurations' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'Miscellaneous') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Miscellaneous Policies\registry.pol"
                    &$LGPOExe /q /s "$WorkingDir\Security-Baselines-X\Miscellaneous Policies\GptTmpl.inf"

                    # Allow all Windows users to use Hyper-V and Windows Sandbox by adding all Windows users to the "Hyper-V Administrators" security group using its SID
                    Get-LocalUser | Where-Object -FilterScript { $_.enabled -eq 'True' } | ForEach-Object -Process { Add-LocalGroupMember -SID 'S-1-5-32-578' -Member "$($_.SID)" -ErrorAction SilentlyContinue }

                    # Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled, doesn't touch affect any other sub-category
                    # For tracking Lock screen unlocks and locks
                    # auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
                    # Using GUID
                    auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable | Out-Null

                    # Query all Audits status
                    # auditpol /get /category:*
                    # Get the list of subcategories and their associated GUIDs
                    # auditpol /list /subcategory:* /r

                    # Event Viewer custom views are saved in "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.
                    if (Test-Path -Path "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script") {
                        Remove-Item -Path "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Recurse -Force
                    }
                    # Creating new sub-folder automatically and extracting the custom views
                    Expand-Archive -Path "$WorkingDir\EventViewerCustomViews.zip" -DestinationPath "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script" -Force
                } 'No' { break MiscellaneousLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-WindowsUpdateConfigurations {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🪟 Windows Update'
            Write-Verbose -Message 'Running Windows Update category'

            :WindowsUpdateLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Windows Update Policies ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Windows Update Configurations' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    # Enable restart notification for Windows update
                    Edit-Registry -path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -key 'RestartNotificationsAllowed2' -value '1' -type 'DWORD' -Action 'AddOrModify'

                    &$LGPOExe /q /m "$WorkingDir\Security-Baselines-X\Windows Update Policies\registry.pol"
                } 'No' { break WindowsUpdateLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-EdgeBrowserConfigurations {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🦔 Edge'
            Write-Verbose -Message 'Running Edge Browser category'

            :MSEdgeLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Edge Browser Configurations ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Edge Browser Configurations' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'Edge') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }
                } 'No' { break MSEdgeLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-CertificateCheckingCommands {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🎟️ Certificates'
            Write-Verbose -Message 'Running Certificate Checking category'

            :CertCheckingLabel switch ($RunUnattended ? 'No' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Certificate Checking category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Certificate Checking Commands' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    try {
                        Invoke-WebRequest -Uri 'https://live.sysinternals.com/sigcheck64.exe' -OutFile 'sigcheck64.exe'
                    }
                    catch {
                        Write-Error -Message 'sigcheck64.exe could not be downloaded from https://live.sysinternals.com' -ErrorAction Continue
                        break CertCheckingLabel
                    }
                    Write-Host -NoNewline "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " User store`n" -ForegroundColor cyan
                    .\sigcheck64.exe -tuv -accepteula -nobanner

                    Write-Host -NoNewline "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " Machine Store`n" -ForegroundColor Blue
                    .\sigcheck64.exe -tv -accepteula -nobanner

                    # Remove the downloaded sigcheck64.exe after using it
                    Remove-Item -Path .\sigcheck64.exe -Force
                } 'No' { break CertCheckingLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-CountryIPBlocking {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)
            if (!$IsAdmin) { break }

            $CurrentMainStep++
            $Host.UI.RawUI.WindowTitle = '🧾 Country IPs'
            Write-Verbose -Message 'Running Country IP Blocking category'

            :IPBlockingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Country IP Blocking category ?")) {
                'Yes' {
                    Write-Progress -Id 0 -Activity 'Country IP Blocking' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    :IPBlockingTerrLabel switch ($RunUnattended ? 'Yes' : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add countries in the State Sponsors of Terrorism list to the Firewall block list?')) {
                        'Yes' {
                            Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt') -ListName 'State Sponsors of Terrorism'
                        } 'No' { break IPBlockingTerrLabel }
                    }
                    :IPBlockingOFACLabel switch ($RunUnattended ? 'No' : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add OFAC Sanctioned Countries to the Firewall block list?')) {
                        'Yes' {
                            Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt') -ListName 'OFAC Sanctioned Countries'
                        } 'No' { break IPBlockingOFACLabel }
                    }
                } 'No' { break IPBlockingLabel }
                'Exit' { exit }
            }
        }
        Function Invoke-NonAdminCommands {
            param([System.Management.Automation.SwitchParameter]$RunUnattended)

            $Host.UI.RawUI.WindowTitle = '🏷️ Non-Admins'
            Write-Verbose -Message 'Running Non-Admin category'

            :NonAdminLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Non-Admin category ?")) {
                'Yes' {
                    $CurrentMainStep = $TotalMainSteps
                    Write-Progress -Id 0 -Activity 'Non-Admin category' -Status "Step $CurrentMainStep/$TotalMainSteps" -PercentComplete ($CurrentMainStep / $TotalMainSteps * 100)

                    foreach ($Item in $RegistryCSVItems) {
                        if ($Item.category -eq 'NonAdmin') {
                            Edit-Registry -path $Item.Path -key $Item.Key -value $Item.Value -type $Item.Type -Action $Item.Action
                        }
                    }

                    # Only suggest restarting the device if Admin related categories were run
                    if (!$Categories -and $IsAdmin) {
                        Write-Host -Object "`r`n"
                        Write-ColorfulText -C Rainbow -I "################################################################################################`r`n"
                        Write-ColorfulText -C MintGreen -I "###  Please Restart your device to completely apply the security measures and Group Policies ###`r`n"
                        Write-ColorfulText -C Rainbow -I "################################################################################################`r`n"
                    }
                } 'No' { break NonAdminLabel }
                'Exit' { exit }
            }
        }
        #Endregion Hardening-Categories-Functions

        switch ($Categories) {
            'WindowsBootManagerRevocations' { Invoke-WindowsBootManagerRevocations -RunUnattended }
            'MicrosoftSecurityBaselines' { Invoke-MicrosoftSecurityBaselines -RunUnattended }
            'Microsoft365AppsSecurityBaselines' { Invoke-Microsoft365AppsSecurityBaselines -RunUnattended }
            'MicrosoftDefender' { Invoke-MicrosoftDefender -RunUnattended }
            'AttackSurfaceReductionRules' { Invoke-AttackSurfaceReductionRules -RunUnattended }
            'BitLockerSettings' { Invoke-BitLockerSettings -RunUnattended }
            'TLSSecurity' { Invoke-TLSSecurity -RunUnattended }
            'LockScreen' { Invoke-LockScreen -RunUnattended }
            'UserAccountControl' { Invoke-UserAccountControl -RunUnattended }
            'WindowsFirewall' { Invoke-WindowsFirewall -RunUnattended }
            'OptionalWindowsFeatures' { Invoke-OptionalWindowsFeatures -RunUnattended }
            'WindowsNetworking' { Invoke-WindowsNetworking -RunUnattended }
            'MiscellaneousConfigurations' { Invoke-MiscellaneousConfigurations -RunUnattended }
            'WindowsUpdateConfigurations' { Invoke-WindowsUpdateConfigurations -RunUnattended }
            'EdgeBrowserConfigurations' { Invoke-EdgeBrowserConfigurations -RunUnattended }
            'CertificateCheckingCommands' { Invoke-CertificateCheckingCommands -RunUnattended }
            'CountryIPBlocking' { Invoke-CountryIPBlocking -RunUnattended }
            'NonAdminCommands' { Invoke-NonAdminCommands -RunUnattended }
            default {
                # Get the values of the ValidateSet attribute of the Categories parameter of the main function
                (Get-Command -Name Protect-WindowsSecurity).Parameters['Categories'].Attributes.ValidValues | ForEach-Object -Process {
                    # Run all of the categories' functions if the user didn't specify any
                    . "Invoke-$_"
                }
            }
        }
    }
    catch {
        # Throw whatever error that occurred
        Throw $_
    }
    finally {
        Write-Verbose -Message 'Finally block is running'

        if ($IsAdmin) {
            # Reverting the PowerShell executables and powercfg.exe allow listings in Controlled folder access
            foreach ($FilePath in (((Get-ChildItem -Path "$PSHOME\*.exe" -File).FullName) + "$env:SystemDrive\Windows\System32\powercfg.exe")) {
                Remove-MpPreference -ControlledFolderAccessAllowedApplications $FilePath
            }

            # restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
            # they will be restored as well, so user customization will remain intact
            if ($null -ne $CFAAllowedAppsBackup) {
                Set-MpPreference -ControlledFolderAccessAllowedApplications $CFAAllowedAppsBackup
            }
        }
        # Remove the working directory
        Remove-Item -Recurse -Path $WorkingDir -Force -ErrorAction SilentlyContinue
        # Disable progress bars
        0..6 | ForEach-Object -Process { Write-Progress -Id $_ -Activity 'Done' -Completed }
        # Restore the title of the PowerShell back to what $it was prior to running the script/module
        $Host.UI.RawUI.WindowTitle = $CurrentPowerShellTitle
        # Set the execution policy back to what it was prior to running the script
        Set-ExecutionPolicy -ExecutionPolicy "$CurrentExecutionPolicy" -Scope 'Process' -Force
    }

    <#
.SYNOPSIS
   Applies the hardening measures described in GitHub repository
.LINK
   https://github.com/HotCakeX/Harden-Windows-Security
.DESCRIPTION
   Applies the hardening measures
.COMPONENT
   PowerShell
.FUNCTIONALITY
   Applies the hardening measures described in GitHub repository
.PARAMETER Categories
    The categories of hardening measures to apply. Use this to only apply specific categories.
    Use this parameter when running the script/module in headless and unattended mode to automatically apply any categories you want without user interaction.
    If not specified, there will be prompts for confirmation before running each category.
.INPUTS
   System.String[]
.OUTPUTS
   System.String
#>
}
Protect-WindowsSecurity

