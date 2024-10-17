# Windows Event Viewer

This document is dedicated to offering various ways to use Event logs to achieve different purposes.

<br>

## How to identify which Windows Firewall rule is responsible for a blocked packet

I've mostly considered this for the [Country IP Blocking category](https://github.com/HotCakeX/Harden-Windows-Security#country-ip-blocking), but you can use it for any purpose.

Before doing this, you need to activate one of the system Audits.

I suggest doing it using GUI because it will have a permanent effect:

![image](https://user-images.githubusercontent.com/118815227/213814954-8ce40aac-bfb0-4973-8677-c77ac232dfb9.png)

<br>

Or you can activate that Audit using this command, but it will only temporarily activate it and it'll be disabled again after you restart Windows.

### For Systems With English Locale Only

```powershell
Auditpol /set /category:"System" /SubCategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

### For Systems With Any Locale

```powershell
Auditpol /set /category:"{69979848-797A-11D9-BED3-505054503030}" /SubCategory:"{0CCE9225-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

<br>

After the Audit is activated, running this PowerShell code will generate an output showing you blocked packets **(if any).**

For example, if you visit a website or access a server that is hosted in one of the countries you blocked, or a connection was made from one of those countries to your device, it will generate an event log that will be visible to you once you run this code.

```powershell
#Requires -RunAsAdministrator
#Requires -Version 7.4
Function Get-BlockedPackets {
    Begin {
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$Events = Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 5152 }
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

        # Create a hashtable of partition numbers and their associated drive letters
        [System.Collections.Generic.Dictionary[string, string]]$DriveLetterMappings = @{}

        # Get all partitions and filter out the ones that don't have a drive letter and then add them to the hashtable with the partition number as the key and the drive letter as the value
        foreach ($Drive in (Get-Partition | Where-Object -FilterScript { $_.DriveLetter })) {
            $DriveLetterMappings[$Drive.PartitionNumber] = $Drive.DriveLetter
        }

        # Define the regex pattern for the device path
        [string]$Pattern = '\\Device\\HarddiskVolume(\d+)\\(.*)$'
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

                # If the application matches the pattern, replace the device path with the drive letter
                if ($_.Application -match $Pattern) {
                    [System.Int64]$HardDiskVolumeNumber = $Matches[1]
                    [System.String]$RemainingPath = $Matches[2]
                    [PSCustomObject]$GetLetter = $DriveLetterMappings[$HardDiskVolumeNumber]
                    [System.IO.FileInfo]$UsablePath = [System.IO.Path]::Combine("$GetLetter`:", $RemainingPath)
                    $_.Application = $_.Application -replace $Pattern, $UsablePath
                }

                # Add the modified object to the $Outputs array
                $Outputs += $_ | Select-Object -Property Application, SourcePort, Protocol, SourceAddress, DestPort, TimeCreated, Direction, DestAddress, ProcessId , FilterOrigin
            }
        }
    }
    End {
        Return $Outputs
    }
}
Get-BlockedPackets
```

<br>

* [Audit Filtering Platform Packet Drop](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-packet-drop)
* [Filter origin audit log improvements](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/filter-origin-documentation)
* [Audit object access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-object-access)

<br>

## How to Get Event Logs from the Miscellaneous Category in PowerShell

This code assumes you've already used the [Harden Windows Security Module](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#miscellaneous-configurations) and the event logs custom views exist on your machine.

```powershell
# Load the XML content from a file or a string
$xml = [xml](Get-Content -Path 'C:\ProgramData\Microsoft\Event Viewer\Views\Hardening Script\Exploit Protection Events.xml')

# Get the QueryList element using XPath
$queryList = $xml.SelectSingleNode("//QueryList")

# Convert the QueryList element to a string
$queryListString = $queryList.OuterXml

$Events = Get-WinEvent -FilterXml $queryListString -Oldest
$Events | Format-Table -AutoSize
```

<br>
