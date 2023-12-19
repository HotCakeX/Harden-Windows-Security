#Requires -RunAsAdministrator
#Requires -Version 7.4
Function Get-BlockedPackets {
    <#
    .SYNOPSIS
        Get blocked packets from the Windows Security event logs according to the specified filter criteria.
        This must be used in an elevated PowerShell session.
    .DESCRIPTION
        The prerequisite for this function is that the Windows Firewall with Advanced Security is enabled.
    .INPUTS
        None
    .OUTPUTS
        System.Object[]
    .LINK
        https://github.com/HotCakeX/Harden-Windows-Security/wiki/Event-Viewer
    .NOTES
        Requires Administrator privileges and PowerShell Core
    #>

    # In the Begin block, execute the following commands once before processing any input
    Begin {
        # Get an array of events with log name 'Security' and ID 5152
        [System.Object[]]$Events = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 5152 }

        # Create an empty array to store the output objects
        [System.Object[]]$Outputs = @()

        # Create an empty hashtable to store the firewall rule names and display names
        [System.Collections.Hashtable]$FirewallGroupPolicy = @{}

        # Loop through each firewall rule from the local policy store (for Firewall rules that are stored in Group Policy)
        foreach ($Rule in Get-NetFirewallRule -PolicyStore localhost) {
            # Add a new entry to the hashtable with the rule name as the key and the display name as the value
            $FirewallGroupPolicy[$Rule.name] = $Rule.DisplayName
        }

        # Loop through each local firewall rule (for Firewall rules that are defined locally in Windows Defender Firewall with Advanced Security)
        foreach ($Rule in Get-NetFirewallRule) {
            # Add a new entry to the hashtable with the rule name as the key and the display name as the value
            $FirewallGroupPolicy[$Rule.name] = $Rule.DisplayName
        }

        Function Get-GlobalRootDrives {
            <#
    .SYNOPSIS
        A function that gets the DriveLetter mappings in the global root namespace
        And fixes these: \Device\Harddiskvolume
    .LINK
        https://superuser.com/questions/1058217/list-every-device-harddiskvolume
    .INPUTS
        None. You cannot pipe objects to this function.
    .OUTPUTS
        System.Objects[]
    #>
            [CmdletBinding()]
            param ()
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
            Add-Type -ErrorAction SilentlyContinue -MemberDefinition $Signature -Name 'Win32Utils' -Namespace 'PInvoke' -Using PInvoke, System.Text -Language CSharp

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
    }

    Process {

        # Loop through each event in the $Events array
        foreach ($Event in $Events) {

            # Convert the event to an XML document
            $Xml = [System.Xml.XmlDocument]$Event.ToXml()

            # Pipe the data elements of the event to the next command
            $Xml.event.eventdata.data |

            # For each data element, do the following
            ForEach-Object -Begin {
                # Create a hashtable with the time created as the first key-value pair
                [System.Collections.Hashtable]$Hash = @{ TimeCreated = [System.DateTime]$Xml.Event.System.TimeCreated.SystemTime }
            } -Process {
                # Add the name and text of the data element as another key-value pair to the hashtable
                $Hash[$_.name] = $_.'#text'
            } -End {
                # Convert the hashtable to a custom object and pipe it to the next command
                [pscustomobject]$Hash
            } |

            # Filter out the objects that have a filter origin property matching any of the specified strings
            Where-Object -Property FilterOrigin -NotMatch 'Stealth|Unknown|Query User Default|WSH Default' | ForEach-Object -Process {

                # If the filter origin is in the hashtable keys
                if ($_.FilterOrigin -in $FirewallGroupPolicy.Keys) {
                    # Replace the filter origin with the display name of the firewall rule from the hashtable
                    $_.FilterOrigin = $FirewallGroupPolicy[$_.FilterOrigin]
                }

                # Create a hashtable with the protocol numbers and names
                [System.String]$ProtocolName = @{ 6 = 'TCP'; 17 = 'UDP' }[[System.Int32]$_.Protocol]

                # If the protocol number is not in the hashtable, keep it as it is, otherwise replace it with the protocol name
                $_.Protocol = if (-not $ProtocolName) { $_.Protocol } else { $ProtocolName }

                # If the direction is equal to '%%14592', set it to 'Outbound', otherwise set it to 'Inbound'
                $_.Direction = $_.Direction -eq '%%14592' ? 'Outbound' : 'Inbound'

                # Get the drive letter mappings in the global root namespace
                [System.Object[]]$DriveLettersGlobalRootFix = Get-GlobalRootDrives

                # Create a regex pattern to match the device path
                [System.String]$Pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$'

                # If the application matches the pattern, replace the device path with the drive letter
                if ($_.Application -match $Pattern) {
                    [System.Int64]$HardDiskVolumeNumber = $Matches[1]
                    [System.String]$RemainingPath = $Matches[2]
                    [PSCustomObject]$GetLetter = $DriveLettersGlobalRootFix | Where-Object -FilterScript { $_.devicepath -eq "\Device\HarddiskVolume$HardDiskVolumeNumber" }
                    [System.IO.FileInfo]$UsablePath = "$($GetLetter.DriveLetter)$RemainingPath"
                    $_.Application = $_.Application -replace $Pattern, $UsablePath
                }

                # Add the modified object to the $Outputs array
                $Outputs += $_ | Select-Object -Property Application, SourcePort, Protocol, SourceAddress, DestPort, TimeCreated, Direction, DestAddress, ProcessId , FilterOrigin
            }
        }
    }
    End {
        # Return the $Outputs array
        Return $Outputs
    }
}

# Call the Get-BlockedPackets function
Get-BlockedPackets
