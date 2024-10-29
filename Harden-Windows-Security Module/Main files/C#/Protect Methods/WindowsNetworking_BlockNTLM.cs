using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class WindowsNetworking
    {
        public static void WindowsNetworking_BlockNTLM()
        {

            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Blocking NTLM", LogTypeIntel.Information);

            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "Block NTLM", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
