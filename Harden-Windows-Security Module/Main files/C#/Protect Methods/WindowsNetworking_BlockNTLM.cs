#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class WindowsNetworking
    {
        public static void WindowsNetworking_BlockNTLM()
        {

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Blocking NTLM", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Networking Policies", "Block NTLM", "registry.pol"), LGPORunner.FileType.POL);

        }
    }
}
