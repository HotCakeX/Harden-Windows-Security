using System;
using System.Management.Automation;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class CountryIPBlocking
    {
        public static void Invoke()
        {
            HardenWindowsSecurity.Logger.LogMessage("Blocking IP ranges of countries in State Sponsors of Terrorism list");

            // PowerShell script
            string script = """
# Terrorists
Import-Module -Name NetSecurity -Force
[System.String]$Name = 'State Sponsors of Terrorism IP range blocking'
# delete previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules
Remove-NetFirewallRule -DisplayName $Name -PolicyStore localhost -ErrorAction SilentlyContinue
[System.String[]]$IPList = (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt')
# converts the list from string to string array
[System.String[]]$IPList = $IPList -split '\r?\n' -ne ''
New-NetFirewallRule -DisplayName $Name -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description $Name -EdgeTraversalPolicy Block -PolicyStore localhost
New-NetFirewallRule -DisplayName $Name -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description $Name -EdgeTraversalPolicy Block -PolicyStore localhost
""";

            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(script);
        }
    }
}
