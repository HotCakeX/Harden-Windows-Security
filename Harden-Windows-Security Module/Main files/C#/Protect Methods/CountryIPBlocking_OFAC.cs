#nullable enable

namespace HardenWindowsSecurity
{
    public partial class CountryIPBlocking
    {
        public static void CountryIPBlocking_OFAC()
        {

            HardenWindowsSecurity.Logger.LogMessage("Blocking IP ranges of countries in OFAC sanction list", LogTypeIntel.Information);

            // another benefit of using LocalStore is that it supports large arrays of IP addresses
            // the default store which goes to Windows firewall store does not support large arrays and throws: "The array bounds are invalid"

            // PowerShell script
            string script = """
# OFAC
Import-Module -Name NetSecurity -Force
[System.String]$Name = 'OFAC Sanctioned Countries IP range blocking'
# delete previous rules (if any) to get new up-to-date IP ranges from the sources and set new rules
Remove-NetFirewallRule -DisplayName $Name -PolicyStore localhost -ErrorAction SilentlyContinue
[System.String[]]$IPList = (Invoke-RestMethod -Uri 'https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt')
# converts the list from string to string array
[System.String[]]$IPList = $IPList -split '\r?\n' -ne ''
New-NetFirewallRule -DisplayName $Name -Direction Inbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description $Name -EdgeTraversalPolicy Block -PolicyStore localhost
New-NetFirewallRule -DisplayName $Name -Direction Outbound -Action Block -LocalAddress Any -RemoteAddress $IPList -Description $Name -EdgeTraversalPolicy Block -PolicyStore localhost
""";

            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(script);
        }
    }
}
