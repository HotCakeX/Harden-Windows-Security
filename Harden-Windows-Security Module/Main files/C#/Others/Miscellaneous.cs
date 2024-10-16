using System;
using System.IO;
using System.Linq;
using System.Management;
using System.Management.Automation;

#nullable enable

namespace HardenWindowsSecurity
{
    public class Miscellaneous
    {
        // Clean up the working directory at the end of each cmdlet
        public static void CleanUp()
        {
            try
            {
                if (Directory.Exists(GlobalVars.WorkingDir))
                {
                    Directory.Delete(GlobalVars.WorkingDir, true);
                }
            }
            catch (Exception ex)
            {
                Logger.LogMessage("Couldn't delete the working directory in the temp folder: " + ex.Message, LogTypeIntel.Warning);
            }
        }

        public static void RequirementsCheck()
        {

            // Check if the user has Administrator privileges before performing the following system requirement checks
            if (UserPrivCheck.IsAdmin())
            {

                // Check if the system is running UEFI firmware
                var firmwareType = FirmwareChecker.CheckFirmwareType();

                if (firmwareType != FirmwareChecker.FirmwareType.FirmwareTypeUefi)
                {
                    throw new InvalidOperationException("Non-UEFI systems are not supported.");
                }

                // run the Confirm-SecureBootUEFI cmdlet to check if Secure Boot is enabled
                using (PowerShell powerShell = PowerShell.Create())
                {
                    _ = powerShell.AddScript("Confirm-SecureBootUEFI");

                    var results = powerShell.Invoke();

                    // Ensure there is at least one result.
                    // Check if the result is null before trying to access it.
                    // Ensure the first result is a boolean and cast it properly.
                    // Verify if isSecureBootEnabled is true.
                    if (results.Count == 0 || results[0] is null || results[0].BaseObject is not bool isSecureBootEnabled || !isSecureBootEnabled)
                    {
                        throw new InvalidOperationException("Secure Boot is not enabled. Please enable it in your UEFI settings and try again.");
                    }
                }

                try
                {
                    // Query the Win32_OperatingSystem class
                    using var searcher = new ManagementObjectSearcher("SELECT OperatingSystemSKU FROM Win32_OperatingSystem");

                    foreach (ManagementObject os in searcher.Get().Cast<ManagementObject>())
                    {
                        var sku = os["OperatingSystemSKU"]?.ToString();

                        // Home edition and Home edition single-language SKUs
                        if (string.Equals(sku, "100", StringComparison.OrdinalIgnoreCase) || string.Equals(sku, "101", StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.LogMessage("The Windows Home edition has been detected, some categories are unavailable and the remaining categories are applied in a best effort fashion.", LogTypeIntel.Warning);
                        }
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogMessage($"An error occurred: {ex.Message}", LogTypeIntel.Error);
                }

                Logger.LogMessage("Checking if TPM is available and enabled...", LogTypeIntel.Information);

                var tpmStatus = TpmStatus.Get();

                if (!tpmStatus.IsActivated || !tpmStatus.IsEnabled)
                {
                    Logger.LogMessage($"TPM is not activated or enabled on this system. BitLockerSettings category will be unavailable - {tpmStatus.ErrorMessage}", LogTypeIntel.Warning);
                }

                if (GlobalVars.MDAVConfigCurrent is null)
                {
                    throw new InvalidOperationException("MDAVConfigCurrent is null.");
                }


                var AMServiceEnabled = PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "AMServiceEnabled");
                if (AMServiceEnabled is not null && !(bool)AMServiceEnabled)
                {
                    throw new InvalidOperationException("Microsoft Defender Anti Malware service is not enabled, please enable it and then try again.");
                }


                var AntispywareEnabled = PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "AntispywareEnabled");
                if (AntispywareEnabled is not null && !(bool)AntispywareEnabled)
                {
                    throw new InvalidOperationException("Microsoft Defender Anti Spyware is not enabled, please enable it and then try again.");
                }


                var AntivirusEnabled = PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "AntivirusEnabled");
                if (AntivirusEnabled is not null && !(bool)AntivirusEnabled)
                {
                    throw new InvalidOperationException("Microsoft Defender Anti Virus is not enabled, please enable it and then try again.");
                }


                string AMRunningMode = PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "AMRunningMode") ?? string.Empty;
                if (!string.Equals(AMRunningMode, "Normal", StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException("Microsoft Defender is not running normally, please remove any 3rd party AV and then try again.");
                }
            }
        }
    }
}
