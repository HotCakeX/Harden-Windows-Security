using System;
using System.IO;
using System.Management;
using System.Management.Automation;

namespace HardeningModule
{
    public class Miscellaneous
    {
        // Clean up the working directory at the end of each cmdlet
        public static void CleanUp()
        {
            if (Directory.Exists(GlobalVars.WorkingDir))
            {
                Directory.Delete(GlobalVars.WorkingDir, true);
            }
        }

        public static void RequirementsCheck()
        {

            // Check if the user has Administrator privileges before performing the following system requirement checks
            if (HardeningModule.UserPrivCheck.IsAdmin())
            {

                // Check if the system is running UEFI firmware
                var firmwareType = HardeningModule.FirmwareChecker.CheckFirmwareType();

                if (firmwareType != HardeningModule.FirmwareChecker.FirmwareType.FirmwareTypeUefi)
                {
                    throw new Exception("Non-UEFI systems are not supported.");
                }

                // run the Confirm-SecureBootUEFI cmdlet to check if Secure Boot is enabled
                using (PowerShell powerShell = PowerShell.Create())
                {
                    powerShell.AddScript("Confirm-SecureBootUEFI");

                    var results = powerShell.Invoke();

                    // Ensure there is at least one result.
                    // Check if the result is null before trying to access it.
                    // Ensure the first result is a boolean and cast it properly.
                    // Verify if isSecureBootEnabled is true.
                    if (results.Count == 0 || results[0] == null || !(results[0].BaseObject is bool isSecureBootEnabled) || !isSecureBootEnabled)
                    {
                        throw new Exception("Secure Boot is not enabled. Please enable it in your UEFI settings and try again.");
                    }
                }

                try
                {
                    // Query the Win32_OperatingSystem class
                    using (var searcher = new ManagementObjectSearcher("SELECT OperatingSystemSKU FROM Win32_OperatingSystem"))
                    {
                        foreach (ManagementObject os in searcher.Get())
                        {
                            var sku = os["OperatingSystemSKU"]?.ToString();

                            // Home edition and Home edition single-language SKUs
                            if (sku == "100" || sku == "101")
                            {
                                Console.WriteLine("Warning: The Windows Home edition has been detected, some categories are unavailable and the remaining categories are applied in a best effort fashion.");
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred: {ex.Message}");
                }

                HardeningModule.VerboseLogger.Write("Checking if TPM is available and enabled...");

                var tpmStatus = HardeningModule.TpmStatus.Get();

                if (!tpmStatus.IsActivated || !tpmStatus.IsEnabled)
                {
                    Console.WriteLine($"TPM is not activated or enabled on this system. BitLockerSettings category will be unavailable - {tpmStatus.ErrorMessage}");
                }

                if (!HardeningModule.GlobalVars.MDAVConfigCurrent.AMServiceEnabled)
                {
                    throw new Exception("Microsoft Defender Anti Malware service is not enabled, please enable it and then try again.");
                }

                if (!HardeningModule.GlobalVars.MDAVConfigCurrent.AntispywareEnabled)
                {
                    throw new Exception("Microsoft Defender Anti Spyware is not enabled, please enable it and then try again.");
                }

                if (!HardeningModule.GlobalVars.MDAVConfigCurrent.AntivirusEnabled)
                {
                    throw new Exception("Microsoft Defender Anti Virus is not enabled, please enable it and then try again.");
                }

                if (HardeningModule.GlobalVars.MDAVConfigCurrent.AMRunningMode != "Normal")
                {
                    throw new Exception($"Microsoft Defender is running in {HardeningModule.GlobalVars.MDAVConfigCurrent.AMRunningMode} state, please remove any 3rd party AV and then try again.");
                }
            }
        }
    }
}
