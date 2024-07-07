using System;
using System.IO;
using System.Collections.Generic;

namespace HardeningModule
{
    public static class GlobalVars
    {
        // Minimum required OS build number
        public const string Requiredbuild = "22621.3155";

        // Current OS build version
        public static readonly int OSBuildNumber = Environment.OSVersion.Version.Build;

        // Update Build Revision (UBR) number
        public static int UBR;

        // Create full OS build number as seen in Windows Settings
        public static string FullOSBuild;

        // Stores the value of $PSScriptRoot in a global variable to allow the internal functions to use it when navigating the module structure
        public static string path;

        // Stores the output of Get-MpComputerStatus which happens early on in the root module .psm1 file
        public static object MDAVConfigCurrent;

        // Stores the output of Get-MpPreference which happens early on in the root module .psm1 file
        public static object MDAVPreferencesCurrent;

        //
        // The following variables are only used by the Confirm-SystemCompliance cmdlet
        //
        public static int TotalNumberOfTrueCompliantValues = 238;

        //
        // The following variables are only used by the Protect-WindowsSecurity cmdlet
        //

        // The working directory used by the Protect-WindowsSecurity cmdlet
        public static string WorkingDir = Path.Combine(Path.GetTempPath(), "HardeningXStuff");

        // The total number of the steps for the parent/main progress bar to render in the Protect-WindowsSecurity cmdlet
        public const int TotalMainSteps = 19;

        // a variable to store the current step number for the progress bar
        public static int CurrentMainStep = 0;

        // Defining a boolean variable to determine whether optional diagnostic data should be enabled for Smart App Control or not
        public static bool ShouldEnableOptionalDiagnosticData = false;

        // Variable indicating whether user launched the module with Offline parameter or not
        public static bool Offline;

        // Path to the Microsoft Security Baselines directory after extraction
        public static string MicrosoftSecurityBaselinePath;

        // The path to the Microsoft 365 Security Baseline directory after extraction
        public static string Microsoft365SecurityBaselinePath;

        // The path to the LGPO.exe utility
        public static string LGPOExe;

        // To store the registry data CSV parse output - Registry.csv
        public static List<HardeningModule.HardeningRegistryKeys.CsvRecord> RegistryCSVItems;

        // To store the Process mitigations CSV parse output used by all cmdlets - ProcessMitigations.csv
        public static List<HardeningModule.ProcessMitigationsParser.ProcessMitigationsRecords> ProcessMitigations;

        // a global variable to save the output of the [HardeningModule.ProtectionCategoriex]::New().GetValidValues() in
        public static string[] HardeningCategorieX;
    }
}
