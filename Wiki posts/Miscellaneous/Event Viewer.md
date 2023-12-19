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

#### [➡️ Link to the `Get-BlockedPackets` Function](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Extras/Get-BlockedPackets.ps1)

* [Audit Filtering Platform Packet Drop](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-packet-drop)
* [Filter origin audit log improvements](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/filter-origin-documentation)
* [Audit object access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-object-access)

<br>

## How to Get Event Logs in Real Time in PowerShell

This code assumes you've already used the [Harden Windows Security Module](https://github.com/HotCakeX/Harden-Windows-Security?tab=readme-ov-file#miscellaneous-configurations) and the event logs custom views exist on your machine.

In this example, any logs generated for Exploit Protection is displayed in real time on PowerShell console. You can modify and improve the displayed output more according to your needs.

#### [➡️ Link to the `Get-EventData` Function](https://github.com/HotCakeX/Harden-Windows-Security/blob/main/Extras/Get-EventData.ps1)

<br>

If you don't want the real time mode and just want to get the logs one time, you can use the following code

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
