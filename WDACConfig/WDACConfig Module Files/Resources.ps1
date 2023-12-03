# Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
$ErrorActionPreference = 'Stop'

# Minimum required OS build number
[System.Decimal]$Requiredbuild = '22621.2428'
# Get OS build version
[System.Decimal]$OSBuild = [System.Environment]::OSVersion.Version.Build
# Get Update Build Revision (UBR) number
[System.Decimal]$UBR = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
# Create full OS build number as seen in Windows Settings
[System.Decimal]$FullOSBuild = "$OSBuild.$UBR"
# Make sure the current OS build is equal or greater than the required build number
if (-NOT ($FullOSBuild -ge $Requiredbuild)) {
    Throw [System.PlatformNotSupportedException] "You are not using the latest build of the Windows OS. A minimum build of $Requiredbuild is required but your OS build is $FullOSBuild`nPlease go to Windows Update to install the updates and then try again."
}

# Get the path to SignTool
function Get-SignTool {
    param(
        [parameter(Mandatory = $false)][System.String]$SignToolExePath
    )
    # If Sign tool path wasn't provided by parameter, try to detect it automatically, if fails, stop the operation
    if (!$SignToolExePath) {
        if ($Env:PROCESSOR_ARCHITECTURE -eq 'AMD64') {
            if ( Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe') {
                $SignToolExePath = 'C:\Program Files (x86)\Windows Kits\*\bin\*\x64\signtool.exe'
            }
            else {
                Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
            }
        }
        elseif ($Env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
            if (Test-Path -Path 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe') {
                $SignToolExePath = 'C:\Program Files (x86)\Windows Kits\*\bin\*\arm64\signtool.exe'
            }
            else {
                Throw [System.IO.FileNotFoundException] 'signtool.exe could not be found'
            }
        }
    }
    try {
        # Validate the SignTool executable
        [System.Version]$WindowsSdkVersion = '10.0.22621.755' # Setting the minimum version of SignTool that is allowed to be executed
        [System.Boolean]$GreenFlag1 = (((Get-Item -Path $SignToolExePath).VersionInfo).ProductVersionRaw -ge $WindowsSdkVersion)
        [System.Boolean]$GreenFlag2 = (((Get-Item -Path $SignToolExePath).VersionInfo).FileVersionRaw -ge $WindowsSdkVersion)
        [System.Boolean]$GreenFlag3 = ((Get-Item -Path $SignToolExePath).VersionInfo).CompanyName -eq 'Microsoft Corporation'
        [System.Boolean]$GreenFlag4 = ((Get-AuthenticodeSignature -FilePath $SignToolExePath).Status -eq 'Valid')
        [System.Boolean]$GreenFlag5 = ((Get-AuthenticodeSignature -FilePath $SignToolExePath).StatusMessage -eq 'Signature verified.')
    }
    catch {
        Throw [System.Security.VerificationException] 'SignTool executable could not be verified.'
    }
    # If any of the 5 checks above fails, the operation stops
    if (!$GreenFlag1 -or !$GreenFlag2 -or !$GreenFlag3 -or !$GreenFlag4 -or !$GreenFlag5) {
        Throw [System.Security.VerificationException] 'The SignTool executable was found but could not be verified. Please download the latest Windows SDK to get the newest SignTool executable. Official download link: http://aka.ms/WinSDK'
    }
    else {
        return $SignToolExePath
    }
}


# Make sure the latest version of the module is installed and if not, automatically update it, clean up any old versions
function Update-self {

    try {
        # Get the last update check time
        [System.DateTime]$UserConfigDate = Get-CommonWDACConfig -LastUpdateCheck
    }
    catch {
        # If the User Config file doesn't exist then set this flag to perform online update check
        [System.Boolean]$PerformOnlineUpdateCheck = $true
    }

    # Ensure these are run only if the User Config file exists and contains a date for last update check
    if (!$PerformOnlineUpdateCheck) {
        # Get the current time
        [System.DateTime]$CurrentDateTime = Get-Date
        # Calculate the minutes elapsed since the last online update check
        [System.Int64]$TimeDiff = ($CurrentDateTime - $UserConfigDate).TotalMinutes
    }

    # Only check for updates if the last attempt occured more than 10 minutes ago or the User Config file for last update check doesn't exist
    # This prevents the module from constantly doing an update check by fetching the version file from GitHub
    if (($TimeDiff -gt 10) -or $PerformOnlineUpdateCheck) {

        [System.Version]$CurrentVersion = (Test-ModuleManifest "$psscriptroot\WDACConfig.psd1").Version.ToString()
        try {
            # First try the GitHub source
            [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt' -ProgressAction SilentlyContinue
        }
        catch {
            try {
                # If GitHub source is unavailable, use the Azure DevOps source
                [System.Version]$LatestVersion = Invoke-RestMethod -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/WDACConfig/version.txt' -ProgressAction SilentlyContinue
            }
            catch {
                Throw [System.Security.VerificationException] 'Could not verify if the latest version of the module is installed, please check your Internet connection. You can optionally bypass the online check by using -SkipVersionCheck parameter.'
            }
        }
        if ($CurrentVersion -lt $LatestVersion) {
            &$WritePink "The currently installed module's version is $CurrentVersion while the latest version is $LatestVersion - Auto Updating the module... 💓"
            Remove-Module -Name 'WDACConfig' -Force
            # Do this if the module was installed properly using Install-module cmdlet
            try {
                Uninstall-Module -Name 'WDACConfig' -AllVersions -Force -ErrorAction Stop
                Install-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force
                Import-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force -Global
            }
            # Do this if module files/folder was just copied to Documents folder and not properly installed - Should rarely happen
            catch {
                Install-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force
                Import-Module -Name 'WDACConfig' -RequiredVersion $LatestVersion -Force -Global
            }
            # Make sure the old version isn't run after update
            Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(152,255,152))Update successful, please run the cmdlet again.$($PSStyle.Reset)"
            break
            return
        }

        # Reset the last update timer to the current time
        Set-CommonWDACConfig -LastUpdateCheck $(Get-Date ) | Out-Null
    }
}


# Increase Code Integrity Operational Event Logs size from the default 1MB to user defined size
function Set-LogSize {
    [CmdletBinding()]
    param ([System.Int64]$LogSize)
    [System.String]$LogName = 'Microsoft-Windows-CodeIntegrity/Operational'
    [System.Diagnostics.Eventing.Reader.EventLogConfiguration]$Log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName
    $Log.MaximumSizeInBytes = $LogSize
    $Log.IsEnabled = $true
    $Log.SaveChanges()
}


# function that takes 2 arrays, one contains file paths and the other contains folder paths. It checks them and shows file paths
# that are not in any of the folder paths. Performs this check recursively too so works if the filepath is in a sub-directory of a folder path
function Test-FilePath {
    param (
        [Parameter(Mandatory = $true)]
        [System.String[]]$FilePath,
        [Parameter(Mandatory = $true)]
        [System.String[]]$DirectoryPath
    )

    # Loop through each file path
    foreach ($file in $FilePath) {
        # Check if the file path is valid
        if (Test-Path -Path $file -PathType 'Leaf') {
            # Get the full path of the file
            $FileFullPath = Resolve-Path -Path $file

            # Initialize a variable to store the result
            [System.Boolean]$Result = $false

            # Loop through each directory path
            foreach ($Directory in $DirectoryPath) {
                # Check if the directory path is valid
                if (Test-Path -Path $Directory -PathType 'Container') {
                    # Get the full path of the directory
                    $DirectoryFullPath = Resolve-Path -Path $Directory

                    # Check if the file path starts with the directory path
                    if ($FileFullPath -like "$DirectoryFullPath\*") {
                        # The file is inside the directory or its sub-directories
                        $Result = $true
                        break # Exit the inner loop
                    }
                }
                else {
                    # The directory path is not valid
                    Write-Warning "The directory path '$Directory' is not valid."
                }
            }

            # Output the file path if it is not inside any of the directory paths
            if (-not $Result) {
                Write-Output -InputObject $FileFullPath
            }
        }
        else {
            # The file path is not valid
            Write-Warning "The file path '$file' is not valid."
        }
    }
}


# Script block that lists every \Device\Harddiskvolume - https://superuser.com/questions/1058217/list-every-device-harddiskvolume
# These are DriveLetter mappings
# Define a script block that fixes the drive letters in the global root namespace
[System.Management.Automation.ScriptBlock]$DriveLettersGlobalRootFixScriptBlock = {

    # Import the kernel32.dll functions using P/Invoke
    [System.String]$Signature = @'
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

'@
    # Add the signature to the current session as a new type
    Add-Type -ErrorAction SilentlyContinue -MemberDefinition $Signature -Name 'Win32Utils' -Namespace 'PInvoke' -Using PInvoke, System.Text

    # Initialize some variables for storing the volume names, paths, and mount points
    [System.UInt32]$lpcchReturnLength = 0
    [System.UInt32]$Max = 65535
    [System.Text.StringBuilder]$SbVolumeName = New-Object -TypeName System.Text.StringBuilder($Max, $Max)
    [System.Text.StringBuilder]$SbPathName = New-Object -TypeName System.Text.StringBuilder($Max, $Max)
    [System.Text.StringBuilder]$SbMountPoint = New-Object -TypeName System.Text.StringBuilder($Max, $Max)

    # Find the first volume in the system and get a handle to it
    [System.IntPtr]$VolumeHandle = [PInvoke.Win32Utils]::FindFirstVolume($SbVolumeName, $Max)

    # Loop through all the volumes in the system
    do {
        # Get the volume name as a string
        [System.String]$Volume = $SbVolumeName.toString()
        # Get the mount point for the volume, if any
        [System.Boolean]$unused = [PInvoke.Win32Utils]::GetVolumePathNamesForVolumeNameW($Volume, $SbMountPoint, $Max, [System.Management.Automation.PSReference]$lpcchReturnLength)
        # Get the device path for the volume, if any
        [System.UInt32]$ReturnLength = [PInvoke.Win32Utils]::QueryDosDevice($Volume.Substring(4, $Volume.Length - 1 - 4), $SbPathName, [System.UInt32]$Max)

        # If the device path is found, create a custom object with the drive mapping information
        if ($ReturnLength) {
            [System.Collections.Hashtable]$DriveMapping = @{
                DriveLetter = $SbMountPoint.toString()
                VolumeName  = $Volume
                DevicePath  = $SbPathName.ToString()
            }
            # Write the custom object to the output stream
            Write-Output -InputObject (New-Object -TypeName PSObject -Property $DriveMapping)
        }
        else {
            # If no device path is found, write a message to the output stream
            Write-Output -InputObject 'No mountpoint found for: ' + $Volume
        }
        # Find the next volume in the system and repeat the loop
    } while ([PInvoke.Win32Utils]::FindNextVolume([System.IntPtr]$VolumeHandle, $SbVolumeName, $Max))

}


### Function to separately capture FileHashes of deleted files and FilePaths of available files from Event Viewer Audit Logs ####
Function Get-AuditEventLogsProcessing {
    param (
        [System.DateTime]$Date
    )

    begin {
        # Get the results of the local disks from the script block
        [System.Object[]]$DriveLettersGlobalRootFix = Invoke-Command -ScriptBlock $DriveLettersGlobalRootFixScriptBlock

        # Defining a custom object to store the results and return it at the end
        $AuditEventLogsProcessingResults = [PSCustomObject]@{
            # Defining object properties as arrays that store file paths
            AvailableFilesPaths = [System.IO.FileInfo[]]@()
            DeletedFileHashes   = [System.IO.FileInfo[]]@()
        }
    }

    process {

        # Event Viewer Code Integrity logs scan
        foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } -ErrorAction SilentlyContinue | Where-Object -FilterScript { $_.TimeCreated -ge $Date } ) {

            $Xml = [System.Xml.XmlDocument]$event.toxml()

            $Xml.event.eventdata.data | ForEach-Object -Begin { $Hash = @{} } -Process { $Hash[$_.name] = $_.'#text' } -End { [pscustomobject]$Hash } | ForEach-Object -Process {

                # Define the regex pattern
                [System.String]$Pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$'

                if ($_.'File Name' -match $Pattern) {
                    [System.Int64]$HardDiskVolumeNumber = $Matches[1]
                    [System.String]$RemainingPath = $Matches[2]
                    [PSCustomObject]$GetLetter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                    [System.IO.FileInfo]$UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                    $_.'File Name' = $_.'File Name' -replace $Pattern, $UsablePath
                }

                # Check if the file is currently on the disk
                if (Test-Path -Path $_.'File Name') {
                    $AuditEventLogsProcessingResults.AvailableFilesPaths += $_.'File Name'
                }

                # If the file is not currently on the disk, extract its hashes from event log
                else {
                    $AuditEventLogsProcessingResults.DeletedFileHashes += $_ | Select-Object FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
                }
            }
        }
    }

    end {
        # return the results as an object
        return $AuditEventLogsProcessingResults
    }
}


# Creates a policy file and requires 2 parameters to supply the file rules and rule references
function New-EmptyPolicy {
    param (
        $RulesContent,
        $RuleRefsContent
    )
    [System.String]$EmptyPolicy = @"
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
$RulesContent
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
$RuleRefsContent
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
    return $EmptyPolicy
}


# Gets the latest Microsoft Recommended block rules, removes its allow all rules and sets HVCI to strict
[System.Management.Automation.ScriptBlock]$GetBlockRulesSCRIPTBLOCK = {
    [System.String]$Rules = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md' -ProgressAction SilentlyContinue).Content -replace "(?s).*``````xml(.*)``````.*", '$1' -replace '<Allow\sID="ID_ALLOW_A_[12]".*/>|<FileRuleRef\sRuleID="ID_ALLOW_A_[12]".*/>', ''
    $Rules | Out-File '.\Microsoft recommended block rules TEMP.xml'
    # Removing empty lines from policy file
    Get-Content -Path '.\Microsoft recommended block rules TEMP.xml' | Where-Object -FilterScript { $_.trim() -ne '' } | Out-File -FilePath '.\Microsoft recommended block rules.xml'
    Remove-Item -Path '.\Microsoft recommended block rules TEMP.xml' -Force
    Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option 3 -Delete
    Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.xml'
    [PSCustomObject]@{
        PolicyFile = 'Microsoft recommended block rules.xml'
    }
}


function Confirm-CertCN {
    <#
    .SYNOPSIS
         Function to check Certificate Common name - used mostly to validate values in UserConfigurations.json
    .INPUTS
        System.String
    .OUTPUTS
        System.Boolean
    #>
    param (
        [System.String]$CN
    )
    [System.String[]]$Certificates = foreach ($cert in (Get-ChildItem -Path 'Cert:\CurrentUser\my')) {
        (($cert.Subject -split ',' | Select-Object -First 1) -replace 'CN=', '').Trim()
    }
    return [System.Boolean]($Certificates -contains $CN ? $true : $false)
}


# script blocks for custom color writing
[System.Management.Automation.ScriptBlock]$WriteHotPink = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,105,180))$($args[0])$($PSStyle.Reset)" }
[System.Management.Automation.ScriptBlock]$WritePink = { Write-Output -InputObject "$($PSStyle.Foreground.FromRGB(255,0,230))$($args[0])$($PSStyle.Reset)" }
[System.Management.Automation.ScriptBlock]$WriteLavender = { Write-Output -InputObject "$($PSStyle.Foreground.FromRgb(255,179,255))$($args[0])$($PSStyle.Reset)" }
[System.Management.Automation.ScriptBlock]$WriteTeaGreen = { Write-Output -InputObject "$($PSStyle.Foreground.FromRgb(133, 222, 119))$($args[0])$($PSStyle.Reset)" }

# Create File Rules based on hash of the files no longer available on the disk and store them in the $Rules variable
function Get-FileRules {
    param ($HashesArray)
    $HashesArray | ForEach-Object -Begin { $i = 1 } -Process {
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AA_$i`" FriendlyName=`"$($_.'File Name') SHA256 Hash`" Hash=`"$($_.'SHA256 Hash')`" />"
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AB_$i`" FriendlyName=`"$($_.'File Name') SHA256 Flat Hash`" Hash=`"$($_.'SHA256 Flat Hash')`" />"
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AC_$i`" FriendlyName=`"$($_.'File Name') SHA1 Hash`" Hash=`"$($_.'SHA1 Hash')`" />"
        $Rules += Write-Output -InputObject "`n<Allow ID=`"ID_ALLOW_AD_$i`" FriendlyName=`"$($_.'File Name') SHA1 Flat Hash`" Hash=`"$($_.'SHA1 Flat Hash')`" />"
        $i++
    }
    return ($Rules.Trim())
}


# Create File Rule Refs based on the ID of the File Rules above and store them in the $RulesRefs variable
function Get-RuleRefs {
    param ($HashesArray)
    $HashesArray | ForEach-Object -Begin { $i = 1 } -Process {
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AA_$i`" />"
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AB_$i`" />"
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AC_$i`" />"
        $RulesRefs += Write-Output -InputObject "`n<FileRuleRef RuleID=`"ID_ALLOW_AD_$i`" />"
        $i++
    }
    return ($RulesRefs.Trim())
}


# Can remove _0 from the ID and SignerId of all the elements in the policy xml file
Function Remove-ZerosFromIDs {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.String]$FilePath
    )
    # Load the xml file
    [System.Xml.XmlDocument]$Xml = Get-Content -Path $FilePath

    # Get all the elements with ID attribute
    $Elements = $Xml.SelectNodes('//*[@ID]')

    # Loop through the elements and replace _0 with empty string in the ID value and SignerId value
    foreach ($Element in $Elements) {
        $Element.ID = $Element.ID -replace '_0', ''
        # Check if the element has child elements with SignerId attribute
        if ($Element.HasChildNodes) {
            # Get the child elements with SignerId attribute
            $childElements = $Element.SelectNodes('.//*[@SignerId]')
            # Loop through the child elements and replace _0 with empty string in the SignerId value
            foreach ($childElement in $childElements) {
                $childElement.SignerId = $childElement.SignerId -replace '_0', ''
            }
        }
    }

    # Get the CiSigners element by name
    $CiSigners = $Xml.SiPolicy.CiSigners

    # Check if the CiSigners element has child elements with SignerId attribute
    if ($CiSigners.HasChildNodes) {
        # Get the child elements with SignerId attribute
        $CiSignersChildren = $CiSigners.ChildNodes
        # Loop through the child elements and replace _0 with empty string in the SignerId value
        foreach ($CiSignerChild in $CiSignersChildren) {
            $CiSignerChild.SignerId = $CiSignerChild.SignerId -replace '_0', ''
        }
    }

    # Save the modified xml file
    $Xml.Save($FilePath)
}


# Moves all User mode AllowedSigners in the User mode signing scenario to the Kernel mode signing scenario and then
# deletes the entire User mode signing scenario block
Function Move-UserModeToKernelMode {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [System.String]$FilePath
    )

    # Load the XML file as an XmlDocument object
    $Xml = [System.Xml.XmlDocument](Get-Content -Path $FilePath)

    # Get the SigningScenario nodes as an array
    $signingScenarios = $Xml.SiPolicy.SigningScenarios.SigningScenario

    # Find the SigningScenario node with Value 131 and store it in a variable
    $signingScenario131 = $signingScenarios | Where-Object -FilterScript { $_.Value -eq '131' }

    # Find the SigningScenario node with Value 12 and store it in a variable
    $signingScenario12 = $signingScenarios | Where-Object -FilterScript { $_.Value -eq '12' }

    # Get the AllowedSigners node from the SigningScenario node with Value 12
    $AllowedSigners12 = $signingScenario12.ProductSigners.AllowedSigners

    # Check if the AllowedSigners node has any child nodes
    if ($AllowedSigners12.HasChildNodes) {
        # Loop through each AllowedSigner node from the SigningScenario node with Value 12
        foreach ($AllowedSigner in $AllowedSigners12.AllowedSigner) {
            # Create a new AllowedSigner node and copy the SignerId attribute from the original node
            # Use the namespace of the parent element when creating the new element
            $NewAllowedSigner = $Xml.CreateElement('AllowedSigner', $signingScenario131.NamespaceURI)
            $NewAllowedSigner.SetAttribute('SignerId', $AllowedSigner.SignerId)

            # Append the new AllowedSigner node to the AllowedSigners node of the SigningScenario node with Value 131
            # out-null to prevent console display
            $signingScenario131.ProductSigners.AllowedSigners.AppendChild($NewAllowedSigner) | Out-Null
        }

        # Remove the SigningScenario node with Value 12 from the XML document
        # out-null to prevent console display
        $Xml.SiPolicy.SigningScenarios.RemoveChild($signingScenario12) | Out-Null
    }

    # Remove Signing Scenario 12 block only if it exists and has no allowed signers (i.e. is empty)
    if ($signingScenario12 -and $AllowedSigners12.count -eq 0) {
        # Remove the SigningScenario node with Value 12 from the XML document
        $Xml.SiPolicy.SigningScenarios.RemoveChild($signingScenario12)
    }

    # Save the modified XML document to a new file
    $Xml.Save($FilePath)
}
