#nullable enable

namespace HardenWindowsSecurity
{
    public class BitLockerSettings
    {
        // Applies all Bitlocker settings hardening category
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🔑 BitLocker");

            HardenWindowsSecurity.Logger.LogMessage("Running the Bitlocker category", LogTypeIntel.Information);

            // Create a path to reuse in the code below
            string basePath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X");

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(basePath, "Bitlocker Policies", "registry.pol"), LGPORunner.FileType.POL);

            // Returns true or false depending on whether Kernel DMA Protection is on or off
            byte BootDMAProtection = HardenWindowsSecurity.SystemInformationClass.BootDmaCheck();
            bool BootDMAProtectionResult = BootDMAProtection == 1;

            // Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
            if (BootDMAProtectionResult)
            {
                HardenWindowsSecurity.Logger.LogMessage("Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.", LogTypeIntel.Information);

                HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(basePath, "Overrides for Microsoft Security Baseline", "Bitlocker DMA", "Bitlocker DMA Countermeasure OFF", "registry.pol"), LGPORunner.FileType.POL);
            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage("Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.", LogTypeIntel.Information);

                HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(basePath, "Overrides for Microsoft Security Baseline", "Bitlocker DMA", "Bitlocker DMA Countermeasure ON", "registry.pol"), LGPORunner.FileType.POL);
            }
        }
    }
}
