using System;
using System.IO;
using System.Collections.Generic;
using System.Management;
using System.Globalization;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public class WindowsNetworking
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the Windows Networking category");

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "registry.pol"), LGPORunner.FileType.POL);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);

            HardenWindowsSecurity.Logger.LogMessage("Disabling LMHOSTS lookup protocol on all network adapters");
            HardenWindowsSecurity.RegistryEditor.EditRegistry(@"Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "EnableLMHOSTS", "0", "DWORD", "AddOrModify");

            HardenWindowsSecurity.Logger.LogMessage("Setting the Network Location of all connections to Public");
            List<ManagementObject> AllCurrentNetworkAdapters = HardenWindowsSecurity.NetConnectionProfiles.Get();

            // Extract InterfaceIndex from each ManagementObject and convert to int array
            int[] InterfaceIndexes = AllCurrentNetworkAdapters
                .Select(n => Convert.ToInt32(n["InterfaceIndex"]))
                .ToArray();

            // Use the extracted InterfaceIndexes in the method to set all of the network locations to public
            HardenWindowsSecurity.NetConnectionProfiles.Set(HardenWindowsSecurity.NetConnectionProfiles.NetworkCategory.Public, InterfaceIndexes, null);
        }
    }
}
