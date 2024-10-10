using System;
using System.IO;
using System.Management.Automation.Host;

#nullable enable

namespace WDACConfig
{
    // This class defines constant variables and makes them available app-domain-wide for PowerShell
    public static class GlobalVars
    {
        // Global variable available app-domain wide to track whether ConfigCI bootstrapping has been run or not
        public static bool ConfigCIBootstrap;

        // User Mode block rules
        public const string MSFTRecommendedBlockRulesURL = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/applications-that-can-bypass-appcontrol.md";

        // Kernel Mode block rules
        public const string MSFTRecommendedDriverBlockRulesURL = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/refs/heads/public/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules.md";

        // Minimum required OS build number
        public const decimal Requiredbuild = 22631.4169M;

        // Current OS build version
        public static decimal OSBuildNumber = Environment.OSVersion.Version.Build;

        // Update Build Revision (UBR) number
        public static int UBR;

        // Stores the value of $PSScriptRoot to allow the internal functions to use it when navigating the module structure
        // It's set by PowerShell code outside of C#
        public static string? ModuleRootPath;

        // Create full OS build number as seen in Windows Settings
        public static string? FullOSBuild;

        // Storing the path to the WDAC Code Integrity Schema XSD file
        public static readonly string CISchemaPath = Path.Combine(
            Environment.GetEnvironmentVariable("SystemDrive") + @"\",
            "Windows", "schemas", "CodeIntegrity", "cipolicy.xsd");

        // Storing the path to the WDACConfig folder in the Program Files
        public static readonly string UserConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WDACConfig");

        // Storing the path to User Config JSON file in the WDACConfig folder in the Program Files
        public static readonly string UserConfigJson = Path.Combine(UserConfigDir, "UserConfigurations", "UserConfigurations.json");

        // Storing the path to the StagingArea folder in the WDACConfig folder in the Program Files
        public static readonly string StagingArea = Path.Combine(UserConfigDir, "StagingArea");

        public static bool VerbosePreference;
        public static bool DebugPreference;

        // The value of the automatic variable $HOST from the PowerShell session
        // Stored using the LoggerInitializer method that is called at the beginning of each cmdlet
        public static PSHost? Host;
    }
}
