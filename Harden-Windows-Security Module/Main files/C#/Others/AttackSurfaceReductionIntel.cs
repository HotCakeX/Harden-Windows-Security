using System;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class AttackSurfaceReductionIntel
    {
        // A dictionary to store the ASR rule IDs and their descriptions
        internal readonly static Dictionary<string, string> ASRTable = new(StringComparer.OrdinalIgnoreCase)
        {
            { "26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes" },
            { "d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands" },
            { "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB" },
            { "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros" },
            { "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes" },
            { "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content" },
            { "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes" },
            { "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" },
            { "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail" },
            { "01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence; age or trusted list criterion" },
            { "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts" },
            { "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription" },
            { "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes" },
            { "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers" },
            { "c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware" },
            { "d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content" },
            { "33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode" },
            { "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools" },
            { "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers" }
        };



        // Correlation between the ComboBox Names in the XAML and the GUID of the ASR Rule they belong to
        // Can't use GUIDs directly in the XAML because they are not valid as XAML element names
        internal readonly static System.Collections.Generic.Dictionary<string, string> ASRRulesCorrelation = new(StringComparer.OrdinalIgnoreCase)
        {
            {"BlockAbuseOfExploitedVulnerableSignedDrivers" , "56a863a9-875e-4185-98a7-b882c64b5ce5"},
            {"BlockAdobeReaderFromCreatingChildProcesses" , "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"},
            {"BlockAllOfficeApplicationsFromCreatingChildProcesses" , "d4f940ab-401b-4efc-aadc-ad5f3c50688a"},
            {"BlockCredentialStealingFromTheWindowsLocalSecurityAuthoritySubsystem" , "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"},
            {"BlockExecutableContentFromEmailClientAndWebmail" , "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"},
            {"BlockExecutableFilesFromRunningUnlessTheyMeetAPrevalenceAgeOrTrustedListCriterion" , "01443614-cd74-433a-b99e-2ecdc07bfc25"},
            {"BlockExecutionOfPotentiallyObfuscatedScripts" , "5beb7efe-fd9a-4556-801d-275e5ffc04cc"},
            {"BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent" , "d3e037e1-3eb8-44c8-a917-57927947596d"},
            {"BlockOfficeApplicationsFromCreatingExecutableContent" , "3b576869-a4ec-4529-8536-b80a7769e899"},
            {"BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses" , "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"},
            {"BlockOfficeCommunicationApplicationFromCreatingChildProcesses" , "26190899-1602-49e8-8b27-eb1d0a1ce869"},
            {"BlockPersistenceThroughWMIEventSubscription" , "e6db77e5-3df2-4cf1-b95a-636979351e5b"},
            {"BlockProcessCreationsOriginatingFromPSExecAndWMICommands" , "d1e49aac-8f56-4280-b9ba-993a6d77406c"},
            {"BlockRebootingMachineInSafeMode" , "33ddedf1-c6e0-47cb-833e-de6133960387"},
            {"BlockUntrustedAndUnsignedProcessesThatRunFromUSB" , "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"},
            {"BlockUseOfCopiedOrImpersonatedSystemTools" , "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"},
            {"BlockWebshellCreationForServers" , "a8f5898e-1dc8-49a9-9878-85004b8a61e6"},
            {"BlockWin32APICallsFromOfficeMacros" , "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"},
            {"UseAdvancedProtectionAgainstRansomware","c1db55ab-c21a-4637-bb3f-a12568109d35" }

        };


        // The reverse form is required for faster processing instead of recreating it
        internal readonly static System.Collections.Generic.Dictionary<string, string> ReversedASRRulesCorrelation = new(StringComparer.OrdinalIgnoreCase)
        {
            {"56a863a9-875e-4185-98a7-b882c64b5ce5", "BlockAbuseOfExploitedVulnerableSignedDrivers"},
            {"7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "BlockAdobeReaderFromCreatingChildProcesses"},
            {"d4f940ab-401b-4efc-aadc-ad5f3c50688a", "BlockAllOfficeApplicationsFromCreatingChildProcesses"},
            {"9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "BlockCredentialStealingFromTheWindowsLocalSecurityAuthoritySubsystem"},
            {"be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "BlockExecutableContentFromEmailClientAndWebmail"},
            {"01443614-cd74-433a-b99e-2ecdc07bfc25", "BlockExecutableFilesFromRunningUnlessTheyMeetAPrevalenceAgeOrTrustedListCriterion"},
            {"5beb7efe-fd9a-4556-801d-275e5ffc04cc", "BlockExecutionOfPotentiallyObfuscatedScripts"},
            {"d3e037e1-3eb8-44c8-a917-57927947596d", "BlockJavaScriptOrVBScriptFromLaunchingDownloadedExecutableContent"},
            {"3b576869-a4ec-4529-8536-b80a7769e899", "BlockOfficeApplicationsFromCreatingExecutableContent"},
            {"75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "BlockOfficeApplicationsFromInjectingCodeIntoOtherProcesses"},
            {"26190899-1602-49e8-8b27-eb1d0a1ce869", "BlockOfficeCommunicationApplicationFromCreatingChildProcesses"},
            {"e6db77e5-3df2-4cf1-b95a-636979351e5b", "BlockPersistenceThroughWMIEventSubscription"},
            {"d1e49aac-8f56-4280-b9ba-993a6d77406c", "BlockProcessCreationsOriginatingFromPSExecAndWMICommands"},
            {"33ddedf1-c6e0-47cb-833e-de6133960387", "BlockRebootingMachineInSafeMode"},
            {"b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "BlockUntrustedAndUnsignedProcessesThatRunFromUSB"},
            {"c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "BlockUseOfCopiedOrImpersonatedSystemTools"},
            {"a8f5898e-1dc8-49a9-9878-85004b8a61e6", "BlockWebshellCreationForServers"},
            {"92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "BlockWin32APICallsFromOfficeMacros"},
            {"c1db55ab-c21a-4637-bb3f-a12568109d35", "UseAdvancedProtectionAgainstRansomware"}
        };

    }
}
