$PSDefaultParameterValues = @{
    'Invoke-WebRequest:HttpVersion'    = '3.0'
    'Invoke-WebRequest:SslProtocol'    = 'Tls12,Tls13'
    'Invoke-RestMethod:HttpVersion'    = '3.0'
    'Invoke-RestMethod:SslProtocol'    = 'Tls12,Tls13'
    'Invoke-WebRequest:ProgressAction' = 'SilentlyContinue'
    'Invoke-RestMethod:ProgressAction' = 'SilentlyContinue'
    'Copy-Item:Force'                  = $true
    'Copy-Item:ProgressAction'         = 'SilentlyContinue'
}
$ErrorActionPreference = 'Stop'

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

    # If GUI is being used, write verbose text and exit
    if ($GUI) {
        Write-Verbose -Message $InputText
        Return
    }

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

            $StringBuilder = New-Object -TypeName System.Text.StringBuilder
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
Function Block-CountryIP {
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
        [parameter(Mandatory = $True)][System.String[]]$IPList,
        [parameter(Mandatory = $True)][System.String]$ListName,
        [Parameter(mandatory = $false)][System.Management.Automation.SwitchParameter]$GUI
    )

    Import-Module -Name NetSecurity -Force

    # converts the list from string to string array
    [System.String[]]$IPList = $IPList -split '\r?\n' -ne ''

    # make sure the list isn't empty
    if ($IPList.count -ne 0) {
        # delete previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules
        Remove-NetFirewallRule -DisplayName "$ListName IP range blocking" -PolicyStore localhost -ErrorAction SilentlyContinue

        [System.Management.Automation.ScriptBlock]$Commands1 = { New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost }
        [System.Management.Automation.ScriptBlock]$Commands2 = { New-NetFirewallRule -DisplayName "$ListName IP range blocking" -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description "$ListName IP range blocking" -EdgeTraversalPolicy Block -PolicyStore localhost }
        if (-NOT $GUI) { &$Commands1; &$Commands2 } else { $null = &$Commands1; $null = &$Commands2 }
    }
    else {
        Write-Warning -Message "The IP list was empty, skipping $ListName"
    }
}
Function Edit-Addons {
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
                        $null = Enable-WindowsOptionalFeature -Online -FeatureName $FeatureName -All -NoRestart
                    }
                    else {
                        $null = Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart
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
                    $null = Get-WindowsCapability -Online | Where-Object -FilterScript { $_.Name -like "*$CapabilityName*" } | Remove-WindowsCapability -Online
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
Function Start-FileDownload {
    Param (
        [Parameter(Mandatory = $false)][System.Collections.Hashtable]$SyncHash,
        [Parameter(Mandatory = $false)][System.Management.Automation.SwitchParameter]$GUI
    )
    if (!([HardeningModule.GlobalVars]::Offline)) { Write-Verbose -Message 'Downloading the required files' }
    [HardeningModule.FileDownloader]::PrepDownloadedFiles(
        ($GUI ? $True : $False),
        ($GUI ? "$($SyncHash['GlobalVars'].LGPOZipPath)" : "$PathToLGPO"),
        ($GUI ? "$($SyncHash['GlobalVars'].MicrosoftSecurityBaselineZipPath)" : "$PathToMSFTSecurityBaselines"),
        ($GUI ? "$($SyncHash['GlobalVars'].Microsoft365AppsSecurityBaselineZipPath)" : "$PathToMSFT365AppsSecurityBaselines")
    )
    Write-Verbose -Message 'Finished downloading/processing the required files'
}
Function New-ToastNotification {
    <#
            .SYNOPSIS
                Displays a toast notification on the screen.
                It uses Windows PowerShell because the required types are not available to PowerShell Core
            #>
    param(
        $SelectedCategories
    )
    # Display a toast notification when the selected categories have been run
    powershell.exe -Sta -Command {

        [System.String]$Title = 'Completed'
        [System.String]$Body = "$($args[0]) selected categories have been run."
        [System.IO.FileInfo]$ImagePath = $args[1]

        # Load the necessary Windows Runtime types for toast notifications
        $null = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]

        # Get the template content for the chosen template
        $Template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::('ToastImageAndText02'))

        # Convert the template to an XML document
        $XML = [System.Xml.XmlDocument]$Template.GetXml()

        # set the image source in the XML
        [System.Xml.XmlElement]$ImagePlaceHolder = $XML.toast.visual.binding.image
        $ImagePlaceHolder.SetAttribute('src', $ImagePath)

        # Set the title text in the XML
        [System.Xml.XmlElement]$TitlePlaceHolder = $XML.toast.visual.binding.text | Where-Object -FilterScript { $_.id -eq '1' }
        [System.Void]$TitlePlaceHolder.AppendChild($XML.CreateTextNode($Title))

        # Set the body text in the XML
        [System.Xml.XmlElement]$BodyPlaceHolder = $XML.toast.visual.binding.text | Where-Object -FilterScript { $_.id -eq '2' }
        [System.Void]$BodyPlaceHolder.AppendChild($XML.CreateTextNode($Body))

        # Load the XML content into a serializable XML document
        $SerializedXml = New-Object -TypeName 'Windows.Data.Xml.Dom.XmlDocument'
        $SerializedXml.LoadXml($XML.OuterXml)

        # Create a new toast notification with the serialized XML
        [Windows.UI.Notifications.ToastNotification]$Toast = [Windows.UI.Notifications.ToastNotification]::new($SerializedXml)

        # Set a tag and group for the notification (used for managing notifications)
        $Toast.Tag = 'Harden Windows Security'
        $Toast.Group = 'Harden Windows Security'

        # Set the notification to expire after 5 seconds
        $Toast.ExpirationTime = [DateTimeOffset]::Now.AddSeconds(5)

        # Create a toast notifier with a specific application ID
        $Notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('Harden Windows Security')

        # Show the notification
        $Notifier.Show($Toast)

        # If the module is running locally, the toast notification image will be taken from the module directory, if not it will be taken from the working directory where it was already downloaded from the GitHub repo
    } -args $SelectedCategories.Count, ("$([HardeningModule.GlobalVars]::Path)\Resources\Media\ToastNotificationIcon.png") *>&1 # To display any error message or other streams from the script block on the console
}
#Endregion Helper-Functions-And-ScriptBlocks

#Region Hardening-Categories-Functions
Function Invoke-MicrosoftSecurityBaselines {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🔐 Security Baselines' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Security Baselines category function'

    :MicrosoftSecurityBaselinesCategoryLabel switch ($RunUnattended ? ($SecBaselines_NoOverrides ? 'Yes' : 'Yes, With the Optional Overrides (Recommended)') : (Select-Option -Options 'Yes', 'Yes, With the Optional Overrides (Recommended)' , 'No', 'Exit' -Message "`nApply Microsoft Security Baseline ?")) {
        'Yes' {
            Write-Verbose -Message "Changing the current directory to '$([HardeningModule.GlobalVars]::MicrosoftSecurityBaselinePath)\Scripts\'"
            Push-Location -Path "$([HardeningModule.GlobalVars]::MicrosoftSecurityBaselinePath)\Scripts\"

            Write-Verbose -Message 'Applying the Microsoft Security Baselines without the optional overrides'
            Write-Progress -Id 0 -Activity 'Microsoft Security Baseline' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers'
            .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>$null
        }
        'Yes, With the Optional Overrides (Recommended)' {
            Write-Verbose -Message "Changing the current directory to '$([HardeningModule.GlobalVars]::MicrosoftSecurityBaselinePath)\Scripts\'"
            Push-Location -Path "$([HardeningModule.GlobalVars]::MicrosoftSecurityBaselinePath)\Scripts\"

            Write-Verbose -Message 'Applying the Microsoft Security Baselines with the optional overrides'
            Write-Progress -Id 0 -Activity 'Microsoft Security Baseline' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers'
            .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>$null

            Start-Sleep -Seconds 1

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Overrides for Microsoft Security Baseline\registry.pol"
            &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Overrides for Microsoft Security Baseline\GptTmpl.inf"

            Write-Verbose -Message 'Re-enabling the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines'
            SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable
        }
        'No' { break MicrosoftSecurityBaselinesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }

    Write-Verbose -Message 'Restoring the original directory location'
    Pop-Location
}
Function Invoke-Microsoft365AppsSecurityBaselines {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🧁 M365 Apps Security' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the M365 Apps Security category function'

    :Microsoft365AppsSecurityBaselinesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Microsoft 365 Apps Security Baseline ?")) {
        'Yes' {
            Write-Verbose -Message 'Applying the Microsoft 365 Apps Security Baseline'
            Write-Progress -Id 0 -Activity 'Microsoft 365 Apps Security Baseline' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            Write-Verbose -Message "Changing the current directory to '$([HardeningModule.GlobalVars]::Microsoft365SecurityBaselinePath)\Scripts\'"
            Push-Location -Path "$([HardeningModule.GlobalVars]::Microsoft365SecurityBaselinePath)\Scripts\"

            Write-Verbose -Message 'Running the official PowerShell script included in the Microsoft 365 Apps Security Baseline file downloaded from Microsoft servers'
            .\Baseline-LocalInstall.ps1 4>$null

            Write-Verbose -Message 'Restoring the original directory location'
            Pop-Location

        } 'No' { break Microsoft365AppsSecurityBaselinesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-MicrosoftDefender {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🍁 MSFT Defender' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Microsoft Defender category function'

    :MicrosoftDefenderLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Microsoft Defender category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Microsoft Defender category'
            Write-Progress -Id 0 -Activity 'Microsoft Defender' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Microsoft Defender Policies\registry.pol"

            # Make sure the parameters are available in the ConfigDefender module before using them
            [System.Collections.Hashtable]$AvailableDefenderParams = (Get-Command -Name Set-MpPreference).Parameters
            Function Set-DefenderConfigWithCheck {
                Param ([System.String]$Name, $Value)
                if ($AvailableDefenderParams.ContainsKey($Name)) {
                    [System.Collections.Hashtable]$Params = @{$Name = $Value }
                    Set-MpPreference @Params
                }
                else {
                    Write-Warning -Message "The parameter $Name is not available yet, restart the OS one more time after updating and try again."
                }
            }

            Write-Verbose -Message 'Optimizing Network Protection Performance of the Microsoft Defender'
            Set-DefenderConfigWithCheck -Name 'AllowSwitchToAsyncInspection' -Value $True

            Write-Verbose -Message 'Enabling Real-time protection and Security Intelligence Updates during OOBE'
            Set-DefenderConfigWithCheck -Name 'OobeEnableRtpAndSigUpdate' -Value $True

            Write-Verbose -Message 'Enabling Intel Threat Detection Technology'
            Set-DefenderConfigWithCheck -Name 'IntelTDTEnabled' -Value $True

            Write-Verbose -Message 'Enabling Restore point scan'
            Set-DefenderConfigWithCheck -Name 'DisableRestorePoint' -Value $False

            Write-Verbose -Message 'Disabling Performance mode of Defender that only applies to Dev drives by lowering security'
            Set-DefenderConfigWithCheck -Name 'PerformanceModeStatus' -Value Disabled

            Write-Verbose -Message 'Setting the Network Protection to block network traffic instead of displaying a warning'
            Set-DefenderConfigWithCheck -Name 'EnableConvertWarnToBlock' -Value $True

            Write-Verbose -Message 'Setting the Brute-Force Protection to use cloud aggregation to block IP addresses that are over 99% likely malicious'
            Set-DefenderConfigWithCheck -Name 'BruteForceProtectionAggressiveness' -Value 1 # 2nd level aggression will come after further testing

            Write-Verbose -Message 'Setting the Brute-Force Protection to prevent suspicious and malicious behaviors'
            Set-DefenderConfigWithCheck -Name 'BruteForceProtectionConfiguredState' -Value 1

            Write-Verbose -Message 'Setting the internal feature logic to determine blocking time for the Brute-Force Protections'
            Set-DefenderConfigWithCheck -Name 'BruteForceProtectionMaxBlockTime' -Value 0

            Write-Verbose -Message 'Setting the Remote Encryption Protection to use cloud intel and context, and block when confidence level is above 90%'
            Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionAggressiveness' -Value 2

            Write-Verbose -Message 'Setting the Remote Encryption Protection to prevent suspicious and malicious behaviors'
            Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionConfiguredState' -Value 1

            Write-Verbose -Message 'Setting the internal feature logic to determine blocking time for the Remote Encryption Protection'
            Set-DefenderConfigWithCheck -Name 'RemoteEncryptionProtectionMaxBlockTime' -Value 0

            Write-Verbose -Message 'Adding OneDrive folders of all the user accounts (personal and work accounts) to the Controlled Folder Access for Ransomware Protection'
            [System.String[]]$DirectoriesToAddToCFA = Get-ChildItem -Path "$env:SystemDrive\Users\*\OneDrive*\" -Directory
            Invoke-CimMethod -Namespace 'Root/Microsoft/Windows/Defender' -ClassName 'MSFT_MpPreference' -MethodName 'Add' -Arguments @{ControlledFolderAccessProtectedFolders = $DirectoriesToAddToCFA }

            Write-Verbose -Message 'Enabling Mandatory ASLR Exploit Protection system-wide'
            Set-ProcessMitigation -System -Enable ForceRelocateImages

            Write-Verbose -Message 'Excluding GitHub Desktop Git executables from mandatory ASLR if they are found'
            foreach ($Item in [HardeningModule.GitHubDesktopFinder]::Find()) {
                Write-Verbose -Message "Excluding $($Item.Name) from mandatory ASLR for GitHub Desktop"
                Set-ProcessMitigation -Name $Item.Name -Disable ForceRelocateImages
            }

            Write-Verbose -Message 'Excluding Git executables from mandatory ASLR if they are found'
            foreach ($Item in [HardeningModule.GitExesFinder]::Find()) {
                Write-Verbose -Message "Excluding $($Item.Name) from mandatory ASLR for Git"
                Set-ProcessMitigation -Name $Item.Name -Disable ForceRelocateImages
            }

            Write-Verbose -Message 'Applying the Process Mitigations'

            # Group the data by ProgramName
            [Microsoft.PowerShell.Commands.GroupInfo[]]$GroupedMitigations = [HardeningModule.GlobalVars]::ProcessMitigations | Group-Object -Property ProgramName
            # Get the current process mitigations
            [System.Object[]]$AllAvailableMitigations = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*')

            # Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
            Write-Verbose -Message 'Removing the existing process mitigations'
            foreach ($Group in $GroupedMitigations) {
                # To separate the filename from full path of the item in the CSV and then check whether it exists in the system registry
                if ($Group.Name -match '\\([^\\]+)$') {
                    if ($Matches[1] -in $AllAvailableMitigations.pschildname) {
                        try {
                            Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Matches[1])" -Recurse -Force
                        }
                        catch {
                            Write-Verbose -Message "Failed to remove $($Matches[1]), it's probably protected by the system."
                        }
                    }
                }
                elseif ($Group.Name -in $AllAvailableMitigations.pschildname) {
                    try {
                        Remove-Item -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($Group.Name)" -Recurse -Force
                    }
                    catch {
                        Write-Verbose -Message "Failed to remove $($Group.Name), it's probably protected by the system."
                    }
                }
            }

            Write-Verbose -Message 'Adding the process mitigations'
            foreach ($Group in $GroupedMitigations) {
                # Get the program name
                [System.String]$ProgramName = $Group.Name

                Write-Verbose -Message "Adding process mitigations for $ProgramName"

                # Get the list of mitigations to enable
                [System.String[]]$EnableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Enable' } | Select-Object -ExpandProperty Mitigation

                # Get the list of mitigations to disable
                [System.String[]]$DisableMitigations = $Group.Group | Where-Object -FilterScript { $_.Action -eq 'Disable' } | Select-Object -ExpandProperty Mitigation

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

            Write-Verbose -Message 'Turning on Data Execution Prevention (DEP) for all applications, including 32-bit programs'
            # Old method: bcdedit.exe /set '{current}' nx AlwaysOn
            # New method using PowerShell cmdlets added in Windows 11
            Set-BcdElement -Element 'nx' -Type 'Integer' -Value '3' -Force

            # Suggest turning on Smart App Control only if it's in Eval mode
            if (([HardeningModule.GlobalVars]::MDAVConfigCurrent).SmartAppControlState -eq 'Eval') {
                :SmartAppControlLabel switch ($RunUnattended ? ($MSFTDefender_SAC ? 'Yes' : 'No' ) : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nTurn on Smart App Control ?")) {
                    'Yes' {
                        Write-Verbose -Message 'Turning on Smart App Control'

                        [HardeningModule.RegistryEditor]::EditRegistry('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy', 'VerifiedAndReputablePolicyState', '1', 'DWORD', 'AddOrModify')

                        # Let the optional diagnostic data be enabled automatically
                        ([HardeningModule.GlobalVars]::ShouldEnableOptionalDiagnosticData) = $True

                    } 'No' { break SmartAppControlLabel }
                    'Exit' { break MainSwitchLabel }
                }
            }

            if ((([HardeningModule.GlobalVars]::ShouldEnableOptionalDiagnosticData) -eq $True) -or (([HardeningModule.GlobalVars]::MDAVConfigCurrent).SmartAppControlState -eq 'On')) {
                Write-Verbose -Message 'Enabling Optional Diagnostic Data because SAC is on or user selected to turn it on'
                &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
            }
            else {
                # Ask user if they want to turn on optional diagnostic data only if Smart App Control is not already turned off
                if (([HardeningModule.GlobalVars]::MDAVConfigCurrent).SmartAppControlState -ne 'Off') {
                    :SmartAppControlLabel2 switch ($RunUnattended ? ($MSFTDefender_NoDiagData ? 'No' : 'Yes') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable Optional Diagnostic Data ?" -ExtraMessage 'Required for Smart App Control usage and evaluation, read the GitHub Readme!')) {
                        'Yes' {
                            Write-Verbose -Message 'Enabling Optional Diagnostic Data'
                            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Microsoft Defender Policies\Optional Diagnostic Data\registry.pol"
                        } 'No' { break SmartAppControlLabel2 }
                        'Exit' { break MainSwitchLabel }
                    }
                }
                else {
                    Write-Verbose -Message 'Smart App Control is turned off, so Optional Diagnostic Data will not be enabled'
                }
            }

            Write-Verbose -Message 'Getting the state of fast weekly Microsoft recommended driver block list update scheduled task'
            [System.String]$BlockListScheduledTaskState = ([HardeningModule.TaskSchedulerHelper]::Get('MSFT Driver Block list update', '\MSFT Driver Block list update\', 'TaskList')).State

            # Create scheduled task for fast weekly Microsoft recommended driver block list update if it doesn't exist or exists but is not Ready/Running
            if (($BlockListScheduledTaskState -notin '2', '3', '4')) {
                :TaskSchedulerCreationLabel switch ($RunUnattended ? ($MSFTDefender_NoScheduledTask ? 'No' : 'Yes') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nCreate scheduled task for fast weekly Microsoft recommended driver block list update ?")) {
                    'Yes' {
                        Write-Verbose -Message 'Creating scheduled task for fast weekly Microsoft recommended driver block list update'

                        # Create a scheduled task action, this defines how to download and install the latest Microsoft Recommended Driver Block Rules
                        [Microsoft.Management.Infrastructure.CimInstance]$Action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
                            -Argument '-NoProfile -WindowStyle Hidden -command "& {try {Invoke-WebRequest -Uri "https://aka.ms/VulnerableDriverBlockList" -OutFile VulnerableDriverBlockList.zip -ErrorAction Stop}catch{exit 1};Expand-Archive -Path .\VulnerableDriverBlockList.zip -DestinationPath "VulnerableDriverBlockList" -Force;Rename-Item -Path .\VulnerableDriverBlockList\SiPolicy_Enforced.p7b -NewName "SiPolicy.p7b" -Force;Copy-Item -Path .\VulnerableDriverBlockList\SiPolicy.p7b -Destination "$env:SystemDrive\Windows\System32\CodeIntegrity" -Force;citool --refresh -json;Remove-Item -Path .\VulnerableDriverBlockList -Recurse -Force;Remove-Item -Path .\VulnerableDriverBlockList.zip -Force; exit 0;}"'

                        # Create a scheduled task principal and assign the SYSTEM account's well-known SID to it so that the task will run under its context
                        [Microsoft.Management.Infrastructure.CimInstance]$TaskPrincipal = New-ScheduledTaskPrincipal -LogonType S4U -UserId 'S-1-5-18' -RunLevel Highest

                        # Create a trigger for the scheduled task. The task will first run one hour after its creation and from then on will run every 7 days, indefinitely
                        [Microsoft.Management.Infrastructure.CimInstance]$Time = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(1) -RepetitionInterval (New-TimeSpan -Days 7)

                        # Register the scheduled task
                        $null = Register-ScheduledTask -Action $Action -Trigger $Time -Principal $TaskPrincipal -TaskPath 'MSFT Driver Block list update' -TaskName 'MSFT Driver Block list update' -Description 'Microsoft Recommended Driver Block List update' -Force

                        # Define advanced settings for the scheduled task
                        [Microsoft.Management.Infrastructure.CimInstance]$TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Compatibility 'Win8' -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 3) -RestartCount 4 -RestartInterval (New-TimeSpan -Hours 6) -RunOnlyIfNetworkAvailable

                        # Add the advanced settings we defined above to the scheduled task
                        $null = Set-ScheduledTask -TaskName 'MSFT Driver Block list update' -TaskPath 'MSFT Driver Block list update' -Settings $TaskSettings
                    } 'No' { break TaskSchedulerCreationLabel }
                    'Exit' { break MainSwitchLabel }
                }
            }
            else {
                Write-Verbose -Message "Scheduled task for fast weekly Microsoft recommended driver block list update already exists and is in $BlockListScheduledTaskState state"
            }

            # Only display this prompt if Engine and Platform update channels are not already set to Beta
            if ((([HardeningModule.GlobalVars]::MDAVPreferencesCurrent).EngineUpdatesChannel -ne '2') -or (([HardeningModule.GlobalVars]::MDAVPreferencesCurrent).PlatformUpdatesChannel -ne '2')) {
                # Set Microsoft Defender engine and platform update channel to beta - Devices in the Windows Insider Program are subscribed to this channel by default.
                :DefenderUpdateChannelsLabel switch ($RunUnattended ? ($MSFTDefender_BetaChannels ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nSet Microsoft Defender engine and platform update channel to beta ?")) {
                    'Yes' {
                        Write-Verbose -Message 'Setting Microsoft Defender engine and platform update channel to beta'
                        Set-MpPreference -EngineUpdatesChannel beta
                        Set-MpPreference -PlatformUpdatesChannel beta
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

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🪷 ASR Rules' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the ASR Rules category function'

    :ASRRulesCategoryLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Attack Surface Reduction Rules category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Attack Surface Reduction Rules category'
            Write-Progress -Id 0 -Activity 'Attack Surface Reduction Rules' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Attack Surface Reduction Rules Policies\registry.pol"
        } 'No' { break ASRRulesCategoryLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-BitLockerSettings {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🔑 BitLocker' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the BitLocker category function'

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
            Write-Verbose -Message 'Running the Bitlocker category'
            Write-Progress -Id 0 -Activity 'Bitlocker Settings' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Bitlocker Policies\registry.pol"

            # returns true or false depending on whether Kernel DMA Protection is on or off
            [System.Boolean]$BootDMAProtection = ([SystemInfo.NativeMethods]::BootDmaCheck()) -ne 0

            # Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
            if ($BootDMAProtection) {
                Write-Host -Object 'Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.' -ForegroundColor Blue
                &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure OFF\Registry.pol"
            }
            else {
                Write-Host -Object 'Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.' -ForegroundColor Blue
                &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Overrides for Microsoft Security Baseline\Bitlocker DMA\Bitlocker DMA Countermeasure ON\Registry.pol"
            }

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
                                    [System.Boolean]$TheyMatch = [HardeningModule.SecureStringComparer]::Compare($Pin1, $Pin2)
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

                            [System.Boolean]$TheyMatch = [HardeningModule.SecureStringComparer]::Compare($Pin1, $Pin2)

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
                                    [System.Boolean]$TheyMatch = [HardeningModule.SecureStringComparer]::Compare($Pin1, $Pin2)
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
                            [System.Boolean]$TheyMatch = [HardeningModule.SecureStringComparer]::Compare($Pin1, $Pin2)
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
            if (-NOT (([HardeningModule.GlobalVars]::MDAVConfigCurrent).IsVirtualMachine)) {

                # Check to see if Hibernate is already set to full and HiberFileType is set to 2 which is Full, 1 is Reduced
                try {
                    [System.Int64]$HiberFileType = Get-ItemPropertyValue -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -ErrorAction SilentlyContinue
                }
                catch {
                    # Do nothing if the key doesn't exist
                }
                if ($HiberFileType -ne 2) {

                    Write-Progress -Id 2 -ParentId 0 -Activity 'Hibernate' -Status 'Setting Hibernate file size to full' -PercentComplete 50
                    $null = &"$env:SystemDrive\Windows\System32\powercfg.exe" /h /type full
                    Write-Progress -Id 2 -Activity 'Setting Hibernate file size to full' -Completed
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

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🛡️ TLS' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the TLS Security category function'

    :TLSSecurityLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun TLS Security category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the TLS Security category'
            Write-Progress -Id 0 -Activity 'TLS Security' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

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
                $null = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $env:COMPUTERNAME).CreateSubKey("SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$_")
            }

            Write-Verbose -Message 'Applying the TLS Security registry settings'
            foreach ($Item in ([HardeningModule.GlobalVars]::RegistryCSVItems)) {
                if ($Item.category -eq 'TLS') {
                    [HardeningModule.RegistryEditor]::EditRegistry($Item.Path, $Item.Key, $Item.Value, $Item.Type, $Item.Action)
                }
            }

            Write-Verbose -Message 'Applying the TLS Security Group Policies'
            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\TLS Security\registry.pol"
        } 'No' { break TLSSecurityLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-LockScreen {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '💻 Lock Screen' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Lock Screen category function'

    :LockScreenLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Lock Screen category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Lock Screen category'
            Write-Progress -Id 0 -Activity 'Lock Screen' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Lock Screen Policies\registry.pol"
            &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Lock Screen Policies\GptTmpl.inf"

            # Apply the Don't display last signed-in policy
            :LockScreenLastSignedInLabel switch ($RunUnattended ? ($LockScreen_NoLastSignedIn ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nDon't display last signed-in on logon screen ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    Write-Verbose -Message "Applying the Don't display last signed-in policy"
                    &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Lock Screen Policies\Don't display last signed-in\GptTmpl.inf"
                } 'No' { break LockScreenLastSignedInLabel }
                'Exit' { break MainSwitchLabel }
            }

            # Enable CTRL + ALT + DEL
            :CtrlAltDelLabel switch ($RunUnattended ? ($LockScreen_CtrlAltDel ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nEnable requiring CTRL + ALT + DEL on lock screen ?")) {
                'Yes' {
                    Write-Verbose -Message 'Applying the Enable CTRL + ALT + DEL policy'
                    &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Lock Screen Policies\Enable CTRL + ALT + DEL\GptTmpl.inf"
                } 'No' { break CtrlAltDelLabel }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break LockScreenLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-UserAccountControl {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '💎 UAC' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the User Account Control category function'

    :UACLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun User Account Control category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the User Account Control category'
            Write-Progress -Id 0 -Activity 'User Account Control' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\User Account Control UAC Policies\GptTmpl.inf"

            # Apply the Hide the entry points for Fast User Switching policy
            :FastUserSwitchingLabel switch ($RunUnattended ? ($UAC_NoFastSwitching ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nHide the entry points for Fast User Switching ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    Write-Verbose -Message 'Applying the Hide the entry points for Fast User Switching policy'
                    &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\User Account Control UAC Policies\Hides the entry points for Fast User Switching\registry.pol"
                } 'No' { break FastUserSwitchingLabel }
                'Exit' { break MainSwitchLabel }
            }

            # Apply the Only elevate executables that are signed and validated policy
            :ElevateSignedExeLabel switch ($RunUnattended ? ($UAC_OnlyElevateSigned ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No', 'Exit' -Message "`nOnly elevate executables that are signed and validated ?" -ExtraMessage 'Read the GitHub Readme!')) {
                'Yes' {
                    Write-Verbose -Message 'Applying the Only elevate executables that are signed and validated policy'
                    &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\User Account Control UAC Policies\Only elevate executables that are signed and validated\GptTmpl.inf"
                } 'No' { break ElevateSignedExeLabel }
                'Exit' { break MainSwitchLabel }
            }
        } 'No' { break UACLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-WindowsFirewall {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🔥 Firewall' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Windows Firewall category function'

    :WindowsFirewallLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Firewall category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Windows Firewall category'
            Write-Progress -Id 0 -Activity 'Windows Firewall' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Windows Firewall Policies\registry.pol"

            Write-Verbose -Message 'Disabling Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules'
            Get-NetFirewallRule |
            Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') } |
            ForEach-Object -Process { Disable-NetFirewallRule -DisplayName $_.DisplayName }

        } 'No' { break WindowsFirewallLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-OptionalWindowsFeatures {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🏅 Optional Features' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Optional Windows Features category function'

    :OptionalFeaturesLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Optional Windows Features category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Optional Windows Features category'
            Write-Progress -Id 0 -Activity 'Optional Windows Features' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            # PowerShell Core (only if installed from Microsoft Store) has problem with these commands: https://github.com/PowerShell/PowerShell/issues/13866#issuecomment-1519066710
            if ($PSHome -like "*$env:SystemDrive\Program Files\WindowsApps\Microsoft.PowerShell*") {
                Write-Verbose -Message 'Importing DISM module to be able to run DISM commands in PowerShell Core installed from MSFT Store'
                Import-Module -Name 'DISM' -UseWindowsPowerShell -Force -WarningAction SilentlyContinue
            }

            Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2'
            Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'MicrosoftWindowsPowerShellV2Root'
            Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'WorkFolders-Client'
            Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Printing-Foundation-Features'
            Edit-Addons -Type Feature -FeatureAction Disabling -FeatureName 'Windows-Defender-ApplicationGuard'
            Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Containers-DisposableClientVM'
            Edit-Addons -Type Feature -FeatureAction Enabling -FeatureName 'Microsoft-Hyper-V'
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
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-WindowsNetworking {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '📶 Networking' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Windows Networking category function'

    :WindowsNetworkingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Windows Networking category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Windows Networking category'
            Write-Progress -Id 0 -Activity 'Windows Networking' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Windows Networking Policies\registry.pol"
            &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Windows Networking Policies\GptTmpl.inf"

            Write-Verbose -Message 'Disabling LMHOSTS lookup protocol on all network adapters'
            [HardeningModule.RegistryEditor]::EditRegistry('Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters', 'EnableLMHOSTS', '0', 'DWORD', 'AddOrModify')

            Write-Verbose -Message 'Setting the Network Location of all connections to Public'
            Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Public
        } 'No' { break WindowsNetworkingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-MiscellaneousConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🥌 Miscellaneous' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Miscellaneous Configurations category function'

    :MiscellaneousLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Miscellaneous Configurations category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Miscellaneous Configurations category'
            Write-Progress -Id 0 -Activity 'Miscellaneous Configurations' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            Write-Verbose -Message 'Applying the Miscellaneous Configurations registry settings'
            foreach ($Item in ([HardeningModule.GlobalVars]::RegistryCSVItems)) {
                if ($Item.category -eq 'Miscellaneous') {
                    [HardeningModule.RegistryEditor]::EditRegistry($Item.Path, $Item.Key, $Item.Value, $Item.Type, $Item.Action)
                }
            }

            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Miscellaneous Policies\registry.pol"
            &$([HardeningModule.GlobalVars]::LGPOExe) /q /s "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Miscellaneous Policies\GptTmpl.inf"

            Write-Verbose -Message 'Adding all Windows users to the "Hyper-V Administrators" security group to be able to use Hyper-V and Windows Sandbox'
            [HardeningModule.LocalUserRetriever]::Get() | Where-Object -FilterScript { $_.enabled -eq 'True' } | ForEach-Object -Process { Add-LocalGroupMember -SID 'S-1-5-32-578' -Member "$($_.SID)" -ErrorAction SilentlyContinue }

            # Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled, doesn't touch affect any other sub-category
            # For tracking Lock screen unlocks and locks
            # auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
            # Using GUID
            Write-Verbose -Message 'Enabling auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category'
            $null = auditpol /set /subcategory:"{0CCE921C-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable

            # Query all Audits status
            # auditpol /get /category:*
            # Get the list of SubCategories and their associated GUIDs
            # auditpol /list /subcategory:* /r

            # Event Viewer custom views are saved in "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.
            if (![System.IO.Directory]::Exists("$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script")) {
                [System.Void] [System.IO.Directory]::CreateDirectory("$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script")
            }

            foreach ($File in [System.IO.Directory]::GetFiles("$([HardeningModule.GlobalVars]::Path)\Resources\EventViewerCustomViews")) {
                [System.IO.File]::Copy($File, "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\$([System.IO.Path]::GetFileName($File))", $true)
            }
        } 'No' { break MiscellaneousLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-WindowsUpdateConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🪟 Windows Update' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Windows Update category function'

    :WindowsUpdateLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Windows Update Policies ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Windows Update category'
            Write-Progress -Id 0 -Activity 'Windows Update Configurations' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            Write-Verbose -Message 'Enabling restart notification for Windows update'
            [HardeningModule.RegistryEditor]::EditRegistry('Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings', 'RestartNotificationsAllowed2', '1', 'DWORD', 'AddOrModify')

            Write-Verbose -Message 'Applying the Windows Update Group Policies'
            &$([HardeningModule.GlobalVars]::LGPOExe) /q /m "$([HardeningModule.GlobalVars]::Path)\Resources\Security-Baselines-X\Windows Update Policies\registry.pol"
        } 'No' { break WindowsUpdateLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-EdgeBrowserConfigurations {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🦔 Edge' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Edge Browser category function'

    :MSEdgeLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nApply Edge Browser Configurations ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Edge Browser category'
            Write-Progress -Id 0 -Activity 'Edge Browser Configurations' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            Write-Verbose -Message 'Applying the Edge Browser registry settings'
            foreach ($Item in ([HardeningModule.GlobalVars]::RegistryCSVItems)) {
                if ($Item.category -eq 'Edge') {
                    [HardeningModule.RegistryEditor]::EditRegistry($Item.Path, $Item.Key, $Item.Value, $Item.Type, $Item.Action)
                }
            }
        } 'No' { break MSEdgeLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-CertificateCheckingCommands {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🎟️ Certificates' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Certificate Checking category function'

    :CertCheckingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Certificate Checking category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Certificate Checking category'
            Write-Progress -Id 0 -Activity 'Certificate Checking Commands' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            try {
                Write-Verbose -Message 'Downloading sigcheck64.exe from https://live.sysinternals.com'
                Invoke-WebRequest -Uri 'https://live.sysinternals.com/sigcheck64.exe' -OutFile 'sigcheck64.exe'
            }
            catch {
                Write-Error -Message 'sigcheck64.exe could not be downloaded from https://live.sysinternals.com' -ErrorAction Continue
                break CertCheckingLabel
            }
            Write-Host -NoNewline -Object "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " Current User store`n" -ForegroundColor cyan
            .\sigcheck64.exe -tuv -accepteula -nobanner

            Write-Host -NoNewline -Object "`nListing valid certificates not rooted to the Microsoft Certificate Trust List in the" -ForegroundColor Yellow; Write-Host -Object " Local Machine Store`n" -ForegroundColor Blue
            .\sigcheck64.exe -tv -accepteula -nobanner

            # Remove the downloaded sigcheck64.exe after using it
            Remove-Item -Path .\sigcheck64.exe -Force
        } 'No' { break CertCheckingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-CountryIPBlocking {
    param(
        [System.Management.Automation.SwitchParameter]$RunUnattended, [System.Management.Automation.SwitchParameter]$GUI
    )

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🧾 Country IPs' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Country IP Blocking category function'

    :IPBlockingLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Country IP Blocking category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Country IP Blocking category'
            Write-Progress -Id 0 -Activity 'Country IP Blocking' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            :IPBlockingTerrLabel switch ($RunUnattended ? 'Yes' : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add countries in the State Sponsors of Terrorism list to the Firewall block list?')) {
                'Yes' {
                    Write-Verbose -Message 'Blocking IP ranges of countries in State Sponsors of Terrorism list'
                    Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt') -ListName 'State Sponsors of Terrorism' -GUI:$GUI
                } 'No' { break IPBlockingTerrLabel }
            }
            :IPBlockingOFACLabel switch ($RunUnattended ? ($CountryIPBlocking_OFAC ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Add OFAC Sanctioned Countries to the Firewall block list?')) {
                'Yes' {
                    Write-Verbose -Message 'Blocking IP ranges of countries in OFAC sanction list'
                    Block-CountryIP -IPList (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt') -ListName 'OFAC Sanctioned Countries' -GUI:$GUI
                } 'No' { break IPBlockingOFACLabel }
            }
        } 'No' { break IPBlockingLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-DownloadsDefenseMeasures {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🎇 Downloads Defense Measures' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Downloads Defense Measures category function'

    :DownloadsDefenseMeasuresLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Downloads Defense Measures category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Downloads Defense Measures category'
            Write-Progress -Id 0 -Activity 'Downloads Defense Measures' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            #Region Installation And Update

            # a flag indicating the WDACConfig module must be downloaded and installed on the system
            [System.Boolean]$ShouldInstallWDACConfigModule = $true

            # Getting the latest available version number of the WDACConfig module
            [System.Version]$WDACConfigLatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt'

            # Getting the latest available version of the WDACConfig module from the local system, if it exists
            [System.Management.Automation.PSModuleInfo]$WDACConfigModuleLocalStatus = Get-Module -ListAvailable -Name 'WDACConfig' -Verbose:$false | Sort-Object -Property Version -Descending | Select-Object -First 1

            # If the WDACConfig module is already installed on the system and its version is greater than or equal to the latest version available on GitHub repo then don't install it again
            if (($null -ne $WDACConfigModuleLocalStatus) -and ($WDACConfigModuleLocalStatus.count -gt 0)) {
                if ($WDACConfigModuleLocalStatus.Version -ge $WDACConfigLatestVersion) {
                    $ShouldInstallWDACConfigModule = $false
                }
                else {
                    [System.String]$ReasonToInstallWDACConfigModule = "the installed WDACConfig module version $($WDACConfigModuleLocalStatus.Version) is less than the latest available version $($WDACConfigLatestVersion)"

                    Write-Verbose -Message 'Removing the WDACConfig module'
                    try {
                        $null = Uninstall-Module -Name 'WDACConfig' -Force -Verbose:$false -AllVersions
                    }
                    catch {}
                }
            }
            else {
                [System.String]$ReasonToInstallWDACConfigModule = 'it is not installed on the system'
            }

            if ($ShouldInstallWDACConfigModule) {
                Write-Verbose -Message "Installing the WDACConfig module because $ReasonToInstallWDACConfigModule"
                Install-Module -Name 'WDACConfig' -Force -Verbose:$false -Scope 'AllUsers' -RequiredVersion $WDACConfigLatestVersion
            }

            #Endregion Installation And Update

            Write-Verbose -Message 'Getting the currently deployed base policy names'
            $CurrentBasePolicyNames = [System.Collections.Generic.HashSet[System.String]](((&"$env:SystemDrive\Windows\System32\CiTool.exe" -lp -json | ConvertFrom-Json).Policies | Where-Object -FilterScript { ($_.IsSystemPolicy -ne 'True') -and ($_.PolicyID -eq $_.BasePolicyID) }).FriendlyName)

            # Only deploy the Downloads-Defense-Measures policy if it is not already deployed
            if (($null -eq $CurrentBasePolicyNames) -or (-NOT ($CurrentBasePolicyNames.Contains('Downloads-Defense-Measures')))) {

                Write-Verbose -Message 'Detecting the Downloads folder path on system'
                [System.IO.FileInfo]$DownloadsPathSystem = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.path
                Write-Verbose -Message "The Downloads folder path on system is $DownloadsPathSystem"

                # Getting the current user's name
                [System.Security.Principal.SecurityIdentifier]$UserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().user.value
                [System.String]$UserName = ([HardeningModule.LocalUserRetriever]::Get() | Where-Object -FilterScript { $_.SID -eq $UserSID }).name

                # Checking if the Edge preferences file exists
                if ([System.IO.File]::Exists("$env:SystemDrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\Preferences")) {

                    Write-Verbose -Message 'Detecting the Downloads path in Edge'
                    [PSCustomObject]$CurrentUserEdgePreference = ConvertFrom-Json -InputObject (Get-Content -Raw -Path "$env:SystemDrive\Users\$UserName\AppData\Local\Microsoft\Edge\User Data\Default\Preferences")
                    [System.IO.FileInfo]$DownloadsPathEdge = $CurrentUserEdgePreference.savefile.default_directory

                    # Ensure there is an Edge browser profile and it was initialized
                    if ((-NOT [System.String]::IsNullOrWhitespace($DownloadsPathEdge.FullName))) {

                        Write-Verbose -Message "The Downloads path in Edge is $DownloadsPathEdge"

                        # Display a warning for now
                        if ($DownloadsPathEdge.FullName -ne $DownloadsPathSystem.FullName) {
                            Write-Warning -Message "The Downloads path in Edge ($($DownloadsPathEdge.FullName)) is different than the system's Downloads path ($($DownloadsPathSystem.FullName))"
                        }
                    }
                }

                Write-Verbose -Message 'Creating and deploying the Downloads-Defense-Measures policy'
                New-DenyWDACConfig -PathWildCards -PolicyName 'Downloads-Defense-Measures' -FolderPath "$DownloadsPathSystem\*" -Deploy -Verbose:$Verbose -SkipVersionCheck -EmbeddedVerboseOutput

            }
            else {
                Write-Verbose -Message 'The Downloads-Defense-Measures policy is already deployed'
            }

            :DangerousScriptHostsBlockingLabel switch ($RunUnattended ? ($DangerousScriptHostsBlocking ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Deploy the Dangerous Script Hosts Blocking WDAC Policy?')) {
                'Yes' {
                    if (($null -eq $CurrentBasePolicyNames) -or (-NOT ($CurrentBasePolicyNames.Contains('Dangerous-Script-Hosts-Blocking')))) {
                        Write-Verbose -Message 'Deploying the Dangerous Script Hosts Blocking WDAC Policy'

                        $null = ConvertFrom-CIPolicy -XmlFilePath "$([HardeningModule.GlobalVars]::Path)\Resources\Dangerous-Script-Hosts-Blocking.xml" -BinaryFilePath "$([HardeningModule.GlobalVars]::WorkingDir)\Dangerous-Script-Hosts-Blocking.cip"
                        $null = CiTool.exe --update-policy "$([HardeningModule.GlobalVars]::WorkingDir)\Dangerous-Script-Hosts-Blocking.cip" -json
                    }
                    else {
                        Write-Verbose -Message 'The Dangerous-Script-Hosts-Blocking policy is already deployed'
                    }
                } 'No' { break DangerousScriptHostsBlockingLabel }
            }

        } 'No' { break DownloadsDefenseMeasuresLabel }
        'Exit' { break MainSwitchLabel }
    }
}
Function Invoke-NonAdminCommands {
    param([System.Management.Automation.SwitchParameter]$RunUnattended)

    ([HardeningModule.GlobalVars]::CurrentMainStep)++
    if (-NOT $RunUnattended) { $Host.UI.RawUI.WindowTitle = '🏷️ Non-Admins' } else { Write-Verbose -Message '=========================' }
    Write-Verbose -Message 'Processing the Non-Admin category function'

    :NonAdminLabel switch ($RunUnattended ? 'Yes' : (Select-Option -Options 'Yes', 'No', 'Exit' -Message "`nRun Non-Admin category ?")) {
        'Yes' {
            Write-Verbose -Message 'Running the Non-Admin category'
            Write-Progress -Id 0 -Activity 'Non-Admin category' -Status "Step $([HardeningModule.GlobalVars]::CurrentMainStep)/$([HardeningModule.GlobalVars]::TotalMainSteps)" -PercentComplete (([HardeningModule.GlobalVars]::CurrentMainStep) / ([HardeningModule.GlobalVars]::TotalMainSteps) * 100)

            Write-Verbose -Message 'Applying the Non-Admin registry settings'
            foreach ($Item in ([HardeningModule.GlobalVars]::RegistryCSVItems)) {
                if ($Item.category -eq 'NonAdmin') {
                    [HardeningModule.RegistryEditor]::EditRegistry($Item.Path, $Item.Key, $Item.Value, $Item.Type, $Item.Action)
                }
            }

            :ClipboardSyncLabel switch ($RunUnattended ? ($ClipboardSync ? 'Yes' : 'No') : (Select-Option -SubCategory -Options 'Yes', 'No' -Message 'Enable Clipboard Syncing with Microsoft Account')) {
                'Yes' {
                    Write-Verbose -Message 'Enabling Clipboard Sync with Microsoft Account'
                    foreach ($Item in ([HardeningModule.GlobalVars]::RegistryCSVItems)) {
                        if ($Item.category -eq 'NonAdmin-ClipboardSync') {
                            [HardeningModule.RegistryEditor]::EditRegistry($Item.Path, $Item.Key, $Item.Value, $Item.Type, $Item.Action)
                        }
                    }
                } 'No' { break ClipboardSyncLabel }
            }

            # Only suggest restarting the device if Admin related categories were run and the code was not running in unattended mode
            if (!$RunUnattended) {
                if (!$Categories -and [HardeningModule.UserPrivCheck]::IsAdmin()) {
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
