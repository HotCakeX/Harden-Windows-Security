using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Management.Automation.Host;
using System.Collections.Concurrent;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class GlobalVars
    {
        // Minimum required OS build number
        public const decimal Requiredbuild = 22621.3155M;

        // Current OS build version
        public static readonly decimal OSBuildNumber = Environment.OSVersion.Version.Build;

        // Update Build Revision (UBR) number
        public static int UBR;

        // Create full OS build number as seen in Windows Settings
        public static string? FullOSBuild;

        // Stores the value of $PSScriptRoot in a global variable to allow the internal functions to use it when navigating the module structure
        public static string? path;

        // Stores the output of Get-MpComputerStatus which happens early on in the root module .psm1 file
        public static dynamic? MDAVConfigCurrent;

        // Stores the output of Get-MpPreference which happens early on in the root module .psm1 file
        public static dynamic? MDAVPreferencesCurrent;

        //
        // The following variables are only used by the Confirm-SystemCompliance cmdlet
        //

        // Total number of Compliant values not equal to N/A
        public static int TotalNumberOfTrueCompliantValues;

        //
        // The following variables are only used by the Protect-WindowsSecurity cmdlet
        //

        // The working directory used by the Protect-WindowsSecurity cmdlet
        public static string WorkingDir = Path.Combine(Path.GetTempPath(), "HardeningXStuff");

        // Defining a boolean variable to determine whether optional diagnostic data should be enabled for Smart App Control or not
        public static bool ShouldEnableOptionalDiagnosticData = false;

        // Variable indicating whether user launched the module with Offline parameter or not
        public static bool Offline;

        // Path to the Microsoft Security Baselines directory after extraction
        public static string? MicrosoftSecurityBaselinePath;

        // The path to the Microsoft 365 Security Baseline directory after extraction
        public static string? Microsoft365SecurityBaselinePath;

        // The path to the LGPO.exe utility
        public static string? LGPOExe;

        // To store the registry data CSV parse output - Registry.csv
        public static List<HardenWindowsSecurity.HardeningRegistryKeys.CsvRecord>? RegistryCSVItems;

        // To store the Process mitigations CSV parse output used by all cmdlets - ProcessMitigations.csv
        public static List<HardenWindowsSecurity.ProcessMitigationsParser.ProcessMitigationsRecords>? ProcessMitigations;

        // a global variable to save the output of the [HardenWindowsSecurity.ProtectionCategoriex]::New().GetValidValues() in
        public static string[]? HardeningCategorieX;

        // the explicit path to save the security_policy.inf file
        public static string securityPolicyInfPath = Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "security_policy.inf");

        // The value of the automatic variable $PSHOME stored during module import in the module root .psm1 file
        public static string? PSHOME;

        // Backup of the current Controlled Folder Access List
        // Used to be restored at the end of the operation
        public static string[]? CFABackup;

        // The value of the automatic variable $HOST from the PowerShell session
        // Stored from the module root .psm1 file
        public static PSHost? Host;

        // The value of the VerbosePreference variable of the PowerShell session
        // stored at the beginning of each cmdlet in the begin block through the Initialize() method
        public static string? VerbosePreference;

        // An object to store the final results of Confirm-SystemCompliance cmdlet
        public static System.Collections.Concurrent.ConcurrentDictionary<System.String, System.Collections.Generic.List<HardenWindowsSecurity.IndividualResult>>? FinalMegaObject;

        // Storing the output of the ini file parsing function
        public static Dictionary<string, Dictionary<string, string>>? SystemSecurityPoliciesIniObject;

        // a variable to store the security policies CSV file parse output
        public static List<HardenWindowsSecurity.SecurityPolicyRecord>? SecurityPolicyRecords;

        // the explicit path to save the CurrentlyAppliedMitigations.xml file
        public static string CurrentlyAppliedMitigations = Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "CurrentlyAppliedMitigations.xml");

        // variable that contains the results of all of the related MDM CimInstances that can be interacted with using Administrator privilege
        public static List<HardenWindowsSecurity.MDMClassProcessor>? MDMResults;

        // To store the Firewall Domain MDM profile parsed JSON output
        public static System.Collections.Hashtable? MDM_Firewall_DomainProfile02;

        // To store the Firewall Private MDM profile parsed JSON output
        public static System.Collections.Hashtable? MDM_Firewall_PrivateProfile02;

        // To store the Firewall Public MDM profile parsed JSON output
        public static System.Collections.Hashtable? MDM_Firewall_PublicProfile02;

        // To store the Windows Update MDM parsed JSON output
        public static System.Collections.Hashtable? MDM_Policy_Result01_Update02;

        // To store the System MDM parsed JSON output
        public static System.Collections.Hashtable? MDM_Policy_Result01_System02;

    }
}
