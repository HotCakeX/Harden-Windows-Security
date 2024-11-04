using Microsoft.Win32;
using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class BitLockerSettings
    {
        /// <summary>
        /// Applies all Bitlocker settings hardening category
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Invoke()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🔑 BitLocker");

            Logger.LogMessage("Running the Bitlocker category", LogTypeIntel.Information);

            // Create a path to reuse in the code below
            string basePath = Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X");

            LGPORunner.RunLGPOCommand(Path.Combine(basePath, "Bitlocker Policies", "registry.pol"), LGPORunner.FileType.POL);

            // Returns true or false depending on whether Kernel DMA Protection is on or off
            byte BootDMAProtection = SystemInformationClass.BootDmaCheck();
            bool BootDMAProtectionResult = BootDMAProtection == 1;

            // Enables or disables DMA protection from Bitlocker Countermeasures based on the status of Kernel DMA protection.
            if (BootDMAProtectionResult)
            {
                Logger.LogMessage("Kernel DMA protection is enabled on the system, disabling Bitlocker DMA protection.", LogTypeIntel.Information);

                LGPORunner.RunLGPOCommand(Path.Combine(basePath, "Overrides for Microsoft Security Baseline", "Bitlocker DMA", "Bitlocker DMA Countermeasure OFF", "registry.pol"), LGPORunner.FileType.POL);
            }
            else
            {
                Logger.LogMessage("Kernel DMA protection is unavailable on the system, enabling Bitlocker DMA protection.", LogTypeIntel.Information);

                LGPORunner.RunLGPOCommand(Path.Combine(basePath, "Overrides for Microsoft Security Baseline", "Bitlocker DMA", "Bitlocker DMA Countermeasure ON", "registry.pol"), LGPORunner.FileType.POL);
            }


            // To detect if Hibernate is enabled and set to full
            // Only perform the check if the system is not a virtual machine
            var isVirtualMachine = PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "IsVirtualMachine");
            // Get the OS Drive encryption status
            BitLocker.BitLockerVolume volumeInfo = BitLocker.GetEncryptedVolumeInfo(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:\\");

            // Only attempt to set Hibernate file size to full if the OS drive is BitLocker encrypted
            // And system is not virtual machine
            if (isVirtualMachine is not null && !(bool)isVirtualMachine && volumeInfo.ProtectionStatus is BitLocker.ProtectionStatus.Protected)
            {

                object? hiberFileType = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power", "HiberFileType", null);
                if (hiberFileType is not null && (int)hiberFileType == 2)
                {
                    Logger.LogMessage("OS Drive is BitLocker encrypted and Hibernate file size is already set to full.", LogTypeIntel.Information);
                }
                else
                {
                    Logger.LogMessage("OS Drive is BitLocker encrypted. Setting the Hibernate file size to full.", LogTypeIntel.Information);
                    _ = PowerShellExecutor.ExecuteScript("""
$null = &"$env:SystemDrive\Windows\System32\powercfg.exe" /h /type full
""");
                }
            }
            else
            {
                Logger.LogMessage("Either the OS Drive is not BitLocker encrypted or the current system is a virtual machine. Skipping setting Hibernate file size to full.", LogTypeIntel.Information);
            }
        }
    }
}
