# Stop operation as soon as there is an error anywhere, unless explicitly specified otherwise
$ErrorActionPreference = 'Stop'

# Minimum required OS build number
[decimal]$Requiredbuild = '22621.2428'
# Get OS build version
[decimal]$OSBuild = [System.Environment]::OSVersion.Version.Build
# Get Update Build Revision (UBR) number
[decimal]$UBR = Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR'
# Create full OS build number as seen in Windows Settings
[decimal]$FullOSBuild = "$OSBuild.$UBR"
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
        [Datetime]$UserConfigDate = Get-CommonWDACConfig -LastUpdateCheck
    }
    catch {
        # If the User Config file doesn't exist then set this flag to perform online update check
        [bool]$PerformOnlineUpdateCheck = $true 
    }

    # Ensure these are run only if the User Config file exists and contains a date for last update check
    if (!$PerformOnlineUpdateCheck) {
        # Get the current time
        [Datetime]$CurrentDateTime = Get-Date
        # Calculate the minutes elapsed since the last online update check
        [int]$TimeDiff = ($CurrentDateTime - $UserConfigDate).TotalMinutes
    }

    # Only check for updates if the last attempt occured more than 10 minutes ago or the User Config file for last update check doesn't exist
    # This prevents the module from constantly doing an update check by fetching the version file from GitHub
    if (($TimeDiff -gt 10) -or $PerformOnlineUpdateCheck) {
        
        $CurrentVersion = (Test-ModuleManifest "$psscriptroot\WDACConfig.psd1").Version.ToString()
        try {
            # First try the GitHub source
            $LatestVersion = Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/version.txt'
        }
        catch {
            try {
                # If GitHub source is unavailable, use the Azure DevOps source
                $LatestVersion = Invoke-RestMethod -Uri 'https://dev.azure.com/SpyNetGirl/011c178a-7b92-462b-bd23-2c014528a67e/_apis/git/repositories/5304fef0-07c0-4821-a613-79c01fb75657/items?path=/WDACConfig/version.txt'        
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
            Write-Output "$($PSStyle.Foreground.FromRGB(152,255,152))Update successful, please run the cmdlet again.$($PSStyle.Reset)"          
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
    $Log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $LogName
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
        if (Test-Path $file -PathType 'Leaf') {
            # Get the full path of the file
            $FileFullPath = Resolve-Path $file

            # Initialize a variable to store the result
            [bool]$Result = $false

            # Loop through each directory path
            foreach ($directory in $DirectoryPath) {
                # Check if the directory path is valid
                if (Test-Path $directory -PathType 'Container') {
                    # Get the full path of the directory
                    $DirectoryFullPath = Resolve-Path $directory

                    # Check if the file path starts with the directory path
                    if ($FileFullPath -like "$DirectoryFullPath\*") {
                        # The file is inside the directory or its sub-directories
                        $Result = $true
                        break # Exit the inner loop
                    }
                }
                else {
                    # The directory path is not valid
                    Write-Warning "The directory path '$directory' is not valid."
                }
            }

            # Output the file path if it is not inside any of the directory paths
            if (-not $Result) {
                Write-Output $FileFullPath
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
[scriptblock]$DriveLettersGlobalRootFixScriptBlock = {
    $signature = @'
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
    Add-Type -ErrorAction SilentlyContinue -MemberDefinition $signature -Name Win32Utils -Namespace PInvoke -Using PInvoke, System.Text

    [UInt32] $lpcchReturnLength = 0
    [UInt32] $Max = 65535
    $sbVolumeName = New-Object System.Text.StringBuilder($Max, $Max)
    $sbPathName = New-Object System.Text.StringBuilder($Max, $Max)
    $sbMountPoint = New-Object System.Text.StringBuilder($Max, $Max)
    [IntPtr] $volumeHandle = [PInvoke.Win32Utils]::FindFirstVolume($sbVolumeName, $Max)
    do {
        $volume = $sbVolumeName.toString()
        $unused = [PInvoke.Win32Utils]::GetVolumePathNamesForVolumeNameW($volume, $sbMountPoint, $Max, [Ref] $lpcchReturnLength)
        $ReturnLength = [PInvoke.Win32Utils]::QueryDosDevice($volume.Substring(4, $volume.Length - 1 - 4), $sbPathName, [UInt32] $Max)
        if ($ReturnLength) {
            $DriveMapping = @{
                DriveLetter = $sbMountPoint.toString()
                VolumeName  = $volume
                DevicePath  = $sbPathName.ToString()
            }
            Write-Output (New-Object PSObject -Property $DriveMapping)
        }
        else {
            Write-Output 'No mountpoint found for: ' + $volume
        } 
    } while ([PInvoke.Win32Utils]::FindNextVolume([IntPtr] $volumeHandle, $sbVolumeName, $Max))
}


### Function to separately capture FileHashes of deleted files and FilePaths of available files from Event Viewer Audit Logs ####
Function Get-AuditEventLogsProcessing {
    param ($Date)

    $DriveLettersGlobalRootFix = Invoke-Command -ScriptBlock $DriveLettersGlobalRootFixScriptBlock

    # Defining a custom object to store and finally return it as results
    $AuditEventLogsProcessingResults = [PSCustomObject]@{
        # Defining object properties as arrays
        AvailableFilesPaths = @()
        DeletedFileHashes   = @()
    }
                      
    # Event Viewer Code Integrity logs scan
    foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Microsoft-Windows-CodeIntegrity/Operational'; ID = 3076 } -ErrorAction SilentlyContinue | Where-Object { $_.TimeCreated -ge $Date } ) {
        $Xml = [xml]$event.toxml()
        $Xml.event.eventdata.data |
        ForEach-Object { $hash = @{} } { $hash[$_.name] = $_.'#text' } { [pscustomobject]$hash } |
        ForEach-Object {
            if ($_.'File Name' -match ($pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$')) {
                $hardDiskVolumeNumber = $Matches[1]
                $remainingPath = $Matches[2]
                $getletter = $DriveLettersGlobalRootFix | Where-Object { $_.devicepath -eq "\Device\HarddiskVolume$hardDiskVolumeNumber" }
                $usablePath = "$($getletter.DriveLetter)$remainingPath"
                $_.'File Name' = $_.'File Name' -replace $pattern, $usablePath
            } # Check if file is currently on the disk
            if (Test-Path $_.'File Name') {
                $AuditEventLogsProcessingResults.AvailableFilesPaths += $_.'File Name' 
            } # If file is not currently on the disk, extract its hashes from event log
            elseif (-NOT (Test-Path $_.'File Name')) {
                $AuditEventLogsProcessingResults.DeletedFileHashes += $_ | Select-Object FileVersion, 'File Name', PolicyGUID, 'SHA256 Hash', 'SHA256 Flat Hash', 'SHA1 Hash', 'SHA1 Flat Hash'
            }
        }
    }
    # return the results as an object
    return $AuditEventLogsProcessingResults
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
[scriptblock]$GetBlockRulesSCRIPTBLOCK = {             
    $Rules = (Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md').Content -replace "(?s).*``````xml(.*)``````.*", '$1' -replace '<Allow\sID="ID_ALLOW_A_[12]".*/>|<FileRuleRef\sRuleID="ID_ALLOW_A_[12]".*/>', ''
    $Rules | Out-File '.\Microsoft recommended block rules TEMP.xml'
    # Removing empty lines from policy file
    Get-Content '.\Microsoft recommended block rules TEMP.xml' | Where-Object { $_.trim() -ne '' } | Out-File '.\Microsoft recommended block rules.xml'                
    Remove-Item '.\Microsoft recommended block rules TEMP.xml' -Force
    Set-RuleOption -FilePath '.\Microsoft recommended block rules.xml' -Option 3 -Delete
    Set-HVCIOptions -Strict -FilePath '.\Microsoft recommended block rules.xml'
    [PSCustomObject]@{
        PolicyFile = 'Microsoft recommended block rules.xml'
    }
}


# Function to check Certificate Common name - used mostly to validate values in UserConfigurations.json
function Confirm-CertCN ([System.String]$CN) {
    $certs = foreach ($cert in (Get-ChildItem 'Cert:\CurrentUser\my')) {
        (($cert.Subject -split ',' | Select-Object -First 1) -replace 'CN=', '').Trim()
    }       
    $certs -contains $CN ? $true : $false
}


# script blocks for custom color writing
[scriptblock]$WriteHotPink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,105,180))$($args[0])$($PSStyle.Reset)" }
[scriptblock]$WritePink = { Write-Output "$($PSStyle.Foreground.FromRGB(255,0,230))$($args[0])$($PSStyle.Reset)" }
[scriptblock]$WriteLavender = { Write-Output "$($PSStyle.Foreground.FromRgb(255,179,255))$($args[0])$($PSStyle.Reset)" }
[scriptblock]$WriteTeaGreen = { Write-Output "$($PSStyle.Foreground.FromRgb(133, 222, 119))$($args[0])$($PSStyle.Reset)" }

# Create File Rules based on hash of the files no longer available on the disk and store them in the $Rules variable
function Get-FileRules {
    param ($HashesArray)                    
    $HashesArray | ForEach-Object -Begin { $i = 1 } -Process {
        $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AA_$i`" FriendlyName=`"$($_.'File Name') SHA256 Hash`" Hash=`"$($_.'SHA256 Hash')`" />"
        $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AB_$i`" FriendlyName=`"$($_.'File Name') SHA256 Flat Hash`" Hash=`"$($_.'SHA256 Flat Hash')`" />"
        $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AC_$i`" FriendlyName=`"$($_.'File Name') SHA1 Hash`" Hash=`"$($_.'SHA1 Hash')`" />"
        $Rules += Write-Output "`n<Allow ID=`"ID_ALLOW_AD_$i`" FriendlyName=`"$($_.'File Name') SHA1 Flat Hash`" Hash=`"$($_.'SHA1 Flat Hash')`" />"
        $i++
    }
    return ($Rules.Trim())
}


# Create File Rule Refs based on the ID of the File Rules above and store them in the $RulesRefs variable
function Get-RuleRefs {
    param ($HashesArray)                 
    $HashesArray | ForEach-Object -Begin { $i = 1 } -Process {
        $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AA_$i`" />"
        $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AB_$i`" />"
        $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AC_$i`" />"
        $RulesRefs += Write-Output "`n<FileRuleRef RuleID=`"ID_ALLOW_AD_$i`" />"
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
    [xml]$Xml = Get-Content -Path $FilePath

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
    $Xml = [xml](Get-Content -Path $FilePath)

    # Get the SigningScenario nodes as an array
    $signingScenarios = $Xml.SiPolicy.SigningScenarios.SigningScenario

    # Find the SigningScenario node with Value 131 and store it in a variable
    $signingScenario131 = $signingScenarios | Where-Object { $_.Value -eq '131' }

    # Find the SigningScenario node with Value 12 and store it in a variable
    $signingScenario12 = $signingScenarios | Where-Object { $_.Value -eq '12' }

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
