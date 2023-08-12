# How to identify which Windows Firewall rule is responsible for a blocked packets

I've mostly considered this for the [Country IP Blocking category](https://github.com/HotCakeX/Harden-Windows-Security#country-ip-blocking) of the hardening script, but you can use it for any purpose.

Before doing this, you need to activate one of the system Audits.

I suggest doing it using GUI because it will have a permanent effect:

![image](https://user-images.githubusercontent.com/118815227/213814954-8ce40aac-bfb0-4973-8677-c77ac232dfb9.png)

<br>

Or you can activate that Audit using this command, but it will only temporarily activate it and it'll be disabled again after you restart Windows.

<br>

```powershell
Auditpol /set /category:"System" /SubCategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
```

<br>

After the Audit is activated, running this PowerShell code will generate an output showing you blocked packets **(if any).**

For example, if you visit a website or access a server that is hosted in one of the countries you blocked, or a connection was made from one of those countries to your device, it will generate an event log that will be visible to you once you run this code. Requires at least `PowerShell 7.3`.

<br>

```powershell
foreach ($event in Get-WinEvent -FilterHashtable @{LogName = 'Security'; ID = 5152 }) {
    $xml = [xml]$event.toxml();
    $xml.event.eventdata.data | 
    ForEach-Object { $hash = @{ TimeCreated = [datetime] $xml.Event.System.TimeCreated.SystemTime } } { $hash[$_.name] = $_.'#text' } { [pscustomobject]$hash } |
    Where-Object FilterOrigin -notmatch 'Stealth|Unknown|Query User Default|WSH Default' | ForEach-Object {      
        if ($_.filterorigin -match ($pattern = '{.+?}')) {        
            $_.FilterOrigin = $_.FilterOrigin -replace $pattern, (Get-NetFirewallRule -Name $Matches[0]).DisplayName
        }
        $protocolName = @{ 6 = 'TCP'; 17 = 'UDP' }[[int] $_.Protocol]
        $_.Protocol = if (-not $protocolName) { $_.Protocol } else { $protocolName }
 
        $_.Direction = $_.Direction -eq '%%14592' ? 'Outbound' : 'Inbound'
        $_
    }
}
```

<br>

## Sources

* [Audit Filtering Platform Packet Drop](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-filtering-platform-packet-drop)
* [Filter origin audit log improvements](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-firewall/filter-origin-documentation)
* [Audit object access](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-object-access)
