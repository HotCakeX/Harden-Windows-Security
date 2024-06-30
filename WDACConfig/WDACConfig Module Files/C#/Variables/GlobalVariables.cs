using System;
using Microsoft.Win32;

namespace WDACConfig
{
    // This class defines constant and readonly variables and makes them available app-domain-wide for PowerShell
    public static class GlobalVars
    {
        // Global variable available app-domain wide to track whether ConfigCI bootstrapping has been run or not
        public static bool ConfigCIBootstrap = false;

        // User Mode block rules
        public const string MSFTRecommendedBlockRulesURL = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md";

        // Kernel Mode block rules
        public const string MSFTRecommendedDriverBlockRulesURL = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md";

        // Minimum required OS build number
        public const string Requiredbuild = "22621.3447";

        // Current OS build version
        public static readonly int OSBuildNumber = Environment.OSVersion.Version.Build;

        // Update Build Revision (UBR) number
        public static readonly int UBR;

        // stores the value of $PSScriptRoot to allow the internal functions to use it when navigating the module structure
        // it's set by PowerShell code outside of C#
        public static string ModuleRootPath = null;

        // Create full OS build number as seen in Windows Settings
        public static readonly string FullOSBuild;

        // Storing the path to the WDAC Code Integrity Schema XSD file
        public static readonly string CISchemaPath = System.IO.Path.Combine(
            Environment.GetEnvironmentVariable("SystemDrive") + @"\",
            "Windows", "schemas", "CodeIntegrity", "cipolicy.xsd");

        // Storing the path to the WDACConfig folder in the Program Files
        public static readonly string UserConfigDir = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WDACConfig");

        // Storing the path to User Config JSON file in the WDACConfig folder in the Program Files
        public static readonly string UserConfigJson = System.IO.Path.Combine(
            UserConfigDir, "UserConfigurations", "UserConfigurations.json");

        // Static constructor for the GlobalVars class
        static GlobalVars()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                if (key != null)
                {
                    object ubrValue = key.GetValue("UBR");
                    if (ubrValue != null && int.TryParse(ubrValue.ToString(), out int ubr))
                    {
                        UBR = ubr;
                    }
                    else
                    {
                        UBR = -1; // Default value in case of error
                    }
                }
                else
                {
                    UBR = -1; // Default value in case the registry key is not found
                }
            }

            // Concatenate OSBuildNumber and UBR to form the final string
            FullOSBuild = $"{OSBuildNumber}.{UBR}";
        }
    }
}
