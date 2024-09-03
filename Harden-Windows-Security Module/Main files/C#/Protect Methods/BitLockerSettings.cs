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

            HardenWindowsSecurity.Logger.LogMessage("Running the Bitlocker category", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Bitlocker Policies", "registry.pol"), LGPORunner.FileType.POL);


            // returns true or false depending on whether Kernel DMA Protection is on or off
            byte BootDMAProtection = HardenWindowsSecurity.SystemInformationClass.BootDmaCheck();

            bool BootDMAProtectionResult = false;

            if (BootDMAProtection == 1)
            {
                BootDMAProtectionResult = true;
            }


            // Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
            if (BootDMAProtectionResult == true)
            {
                HardenWindowsSecurity.Logger.LogMessage("Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.", LogTypeIntel.Information);

                HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Overrides for Microsoft Security Baseline", "Bitlocker DMA", "Bitlocker DMA Countermeasure OFF", "registry.pol"), LGPORunner.FileType.POL);
            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage("Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.", LogTypeIntel.Information);

                HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Overrides for Microsoft Security Baseline", "Bitlocker DMA", "Bitlocker DMA Countermeasure ON", "registry.pol"), LGPORunner.FileType.POL);
            }
        }
    }
}
