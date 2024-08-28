using System;
using System.Collections.Generic;
using System.Management;
using System.Management.Automation;
using System.Security.Principal;

#nullable enable

namespace HardenWindowsSecurity
{
    public class ComplianceCategoriex : IValidateSetValuesGenerator
    {
        public string[] GetValidValues()
        {
            string[] categoriex = new string[]
            {
            "MicrosoftDefender", // 54 + Number of Process Mitigations which are dynamically increased
            "AttackSurfaceReductionRules", // 19 rules
            "BitLockerSettings", // 21 + conditional item for Hibernation check (only available on non-VMs) + Number of Non-OS drives which are dynamically increased
            "TLSSecurity", // 21
            "LockScreen", // 14
            "UserAccountControl", // 4
            "DeviceGuard", // 8
            "WindowsFirewall", // 19
            "OptionalWindowsFeatures", // 14
            "WindowsNetworking", // 9
            "MiscellaneousConfigurations", // 17
            "WindowsUpdateConfigurations", // 14
            "EdgeBrowserConfigurations", // 14
            "NonAdminCommands" // 11
            };
            return categoriex;
        }
    }

    // # This class is the orchestrator of the hardening categories deciding which one of them is allowed to run
    public class ProtectionCategoriex
    {
        // a method to detect Windows edition SKU number
        public static bool IsWindowsHome()
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher("SELECT OperatingSystemSKU FROM Win32_OperatingSystem"))
            {
                foreach (ManagementObject os in searcher.Get())
                {
                    // check for SKU of Windows Home and Windows Home Single Language
                    int sku = (int)(uint)os["OperatingSystemSKU"];
                    if (sku == 101 || sku == 100)
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        // Detect if TPM is present on the system
        public static bool IsTpmPresentAndEnabled()
        {
            try
            {
                // Create a ManagementScope for the TPM namespace
                ManagementScope scope = new ManagementScope(@"\\.\root\CIMv2\Security\MicrosoftTpm");
                scope.Connect();

                // Create an ObjectQuery to query the Win32_Tpm class
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Tpm");

                // Create a ManagementObjectSearcher to execute the query
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);

                // Get the TPM instances
                ManagementObjectCollection queryCollection = searcher.Get();

                if (queryCollection.Count > 0)
                {
                    return true;
                    //   foreach (ManagementObject tpm in queryCollection)
                    //    {
                    //     HardenWindowsSecurity.Logger.LogMessage("TPM is present on this system.");
                    //     HardenWindowsSecurity.Logger.LogMessage("TPM Version: " + tpm["SpecVersion"]);
                    //    }
                }
            }
            catch (Exception ex)
            {
                throw new Exception("An error occurred while checking TPM status.", ex);
            }
            return false;
        }

        // Main method of the class to return the final authorized categories
        public static string[] GetValidValues()
        {
            // if running under unelevated context then only return the NonAdminCommands category
            if (!HardenWindowsSecurity.UserPrivCheck.IsAdmin()) return new string[] { "NonAdminCommands" };

            HashSet<string> categoriex = new HashSet<string>
        {
            "MicrosoftSecurityBaselines",
            "Microsoft365AppsSecurityBaselines",
            "MicrosoftDefender",
            "AttackSurfaceReductionRules",
            "BitLockerSettings",
            "TLSSecurity",
            "LockScreen",
            "UserAccountControl",
            "WindowsFirewall",
            "OptionalWindowsFeatures",
            "WindowsNetworking",
            "MiscellaneousConfigurations",
            "WindowsUpdateConfigurations",
            "EdgeBrowserConfigurations",
            "CertificateCheckingCommands",
            "CountryIPBlocking",
            "DownloadsDefenseMeasures",
            "NonAdminCommands"
        };

            // Remove the categories that are not applicable to Windows Home editions
            if (IsWindowsHome())
            {
                string[] homeEditionCategories = new string[]
                {
                "BitLockerSettings",
                "DownloadsDefenseMeasures",
                "TLSSecurity",
                "AttackSurfaceReductionRules",
                "MicrosoftSecurityBaselines",
                "Microsoft365AppsSecurityBaselines",
                "CountryIPBlocking"
                };
                foreach (string category in homeEditionCategories)
                {
                    categoriex.Remove(category);
                }
            }

            // Remove the BitLockerSettings category if TPM is not present on the systems
            if (!IsTpmPresentAndEnabled())
            {
                categoriex.Remove("BitLockerSettings");
            }

            return new List<string>(categoriex).ToArray();
        }
    }
}
