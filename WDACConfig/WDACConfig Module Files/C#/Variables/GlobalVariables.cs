using System;
using System.IO;
using System.Globalization;
using System.Management.Automation.Host;

namespace WDACConfig
{
    // This class defines constant variables and makes them available app-domain-wide for PowerShell
    public static class GlobalVars
    {
        // Global variable available app-domain wide to track whether ConfigCI bootstrapping has been run or not
        public static bool ConfigCIBootstrap = false;

        // User Mode block rules
        public const string MSFTRecommendedBlockRulesURL = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/applications-that-can-bypass-wdac.md";

        // Kernel Mode block rules
        public const string MSFTRecommendedDriverBlockRulesURL = "https://raw.githubusercontent.com/MicrosoftDocs/windows-itpro-docs/public/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules.md";

        // Minimum required OS build number
        public const decimal Requiredbuild = 22621.3447M;

        // Current OS build version
        public static decimal OSBuildNumber = Environment.OSVersion.Version.Build;

        // Update Build Revision (UBR) number
        public static int UBR;

        // stores the value of $PSScriptRoot to allow the internal functions to use it when navigating the module structure
        // it's set by PowerShell code outside of C#
        public static string ModuleRootPath;

        // Create full OS build number as seen in Windows Settings
        public static string FullOSBuild;

        // Storing the path to the WDAC Code Integrity Schema XSD file
        public static readonly string CISchemaPath = System.IO.Path.Combine(
            Environment.GetEnvironmentVariable("SystemDrive") + @"\",
            "Windows", "schemas", "CodeIntegrity", "cipolicy.xsd");

        // Storing the path to the WDACConfig folder in the Program Files
        public static readonly string UserConfigDir = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WDACConfig");

        // Storing the path to User Config JSON file in the WDACConfig folder in the Program Files
        public static readonly string UserConfigJson = System.IO.Path.Combine(UserConfigDir, "UserConfigurations", "UserConfigurations.json");

        // The VerbosePreference variable of the PowerShell session
        public static string VerbosePreference;

        // The DebugPreference variable of the PowerShell session
        public static string DebugPreference;

        // The value of the automatic variable $HOST from the PowerShell session
        // Stored using the LoggerInitializer method that is called at the beginning of each cmdlet
        public static PSHost Host;
    }
}
