using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class WindowsFirewall
    {
        /// <summary>
        /// Runs the Windows Firewall hardening category
        /// </summary>
        /// <exception cref="System.ArgumentNullException"></exception>
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🔥 Firewall");

            HardenWindowsSecurity.Logger.LogMessage("Running the Windows Firewall category", LogTypeIntel.Information);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Firewall Policies", "registry.pol"), LGPORunner.FileType.POL);

            HardenWindowsSecurity.Logger.LogMessage("Setting the Network Location of all connections to Public", LogTypeIntel.Information);
            List<ManagementObject> AllCurrentNetworkAdapters = HardenWindowsSecurity.NetConnectionProfiles.Get();

            // Extract InterfaceIndex from each ManagementObject and convert to int array
            int[] InterfaceIndexes = AllCurrentNetworkAdapters
                .Select(n => Convert.ToInt32(n["InterfaceIndex"], CultureInfo.InvariantCulture))
                .ToArray();

            // Use the extracted InterfaceIndexes in the method to set all of the network locations to public
            bool ReturnResult = HardenWindowsSecurity.NetConnectionProfiles.Set(HardenWindowsSecurity.NetConnectionProfiles.NetworkCategory.Public, InterfaceIndexes, null);

            if (!ReturnResult)
            {
                HardenWindowsSecurity.Logger.LogMessage("An error occurred while setting the Network Location of all connections to Public", LogTypeIntel.ErrorInteractionRequired);
            }

            HardenWindowsSecurity.Logger.LogMessage("Disabling Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules", LogTypeIntel.Information);


            _ = HardenWindowsSecurity.PowerShellExecutor.ExecuteScript("""
Get-NetFirewallRule |
Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') } |
ForEach-Object -Process { Disable-NetFirewallRule -DisplayName $_.DisplayName }
""");

        }
    }
}
