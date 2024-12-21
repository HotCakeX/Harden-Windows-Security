using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;

namespace HardenWindowsSecurity;

    public static class UnprotectWindowsSecurity
    {
        /// <summary>
        /// Performs the main tasks for removing protections from Windows that were applied during the protection phase
        /// </summary>
        public static void Unprotect()
        {

            #region
            Logger.LogMessage("Removing all of the group policies from the system.", LogTypeIntel.Information);

            string GroupPolicyDirectoryLocation = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "GroupPolicy");

            if (Directory.Exists(GroupPolicyDirectoryLocation))
            {
                Directory.Delete(GroupPolicyDirectoryLocation, true);
            }
            #endregion


            #region registry keys
            Logger.LogMessage("Deleting all the registry keys created during protection.", LogTypeIntel.Information);

            foreach (HardeningRegistryKeys.CsvRecord Item in GlobalVars.RegistryCSVItems)
            {
                RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, "Delete");
            }

            // To completely remove the Edge policy since only its sub-keys are removed by the command above
            using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge", writable: true))
            {
                // Delete the specified subkey and its contents if it exists
                key?.DeleteSubKeyTree("TLSCipherSuiteDenyList", throwOnMissingSubKey: false);
            }

            // Set a tattooed Group policy for SvcHost.exe process mitigations back to disabled state
            RegistryEditor.EditRegistry(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SCMConfig", "EnableSvchostMitigationPolicy", "0", "DWORD", "AddOrModify");

            // Set a tattooed Group policy for Long path support to disabled state
            RegistryEditor.EditRegistry(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem", "LongPathsEnabled", "0", "DWORD", "AddOrModify");

            #endregion


            #region Advanced Microsoft Defender features
            Logger.LogMessage("Reverting the advanced protections in the Microsoft Defender.", LogTypeIntel.Information);
            ConfigDefenderHelper.ManageMpPreference("AllowSwitchToAsyncInspection", false, true);
            ConfigDefenderHelper.ManageMpPreference("DisableRestorePoint", true, true);
            ConfigDefenderHelper.ManageMpPreference("EnableConvertWarnToBlock", false, true);
            ConfigDefenderHelper.ManageMpPreference("BruteForceProtectionLocalNetworkBlocking", false, true);
            ConfigDefenderHelper.ManageMpPreference("EnableEcsConfiguration", false, true);
            ConfigDefenderHelper.ManageMpPreference("EngineUpdatesChannel", "0", true);
            ConfigDefenderHelper.ManageMpPreference("PlatformUpdatesChannel", "0", true);
            #endregion


            #region Group Policies
            Logger.LogMessage("Restoring the default Security group policies", LogTypeIntel.Information);

            // if LGPO doesn't already exist in the working directory, then download it
            // No ActivityTracker is implemented in here because this file download only happens
            // When this method is run from PowerShell
            // When this method is run from the GUI, check for existence of LGPO and downloading it will happen in that code
            if (!Path.Exists(GlobalVars.LGPOExe))
            {
                Logger.LogMessage("LGPO.exe doesn't exist, downloading it.", LogTypeIntel.Information);
                AsyncDownloader.PrepDownloadedFiles(GlobalVars.LGPOExe, null, null, true);
            }
            else
            {
                Logger.LogMessage("LGPO.exe already exists, skipping downloading it.", LogTypeIntel.Information);
            }

            // Apply the default security policy on the system
            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path!, "Resources", "Default Security Policy.inf"), LGPORunner.FileType.INF, Path.Combine(GlobalVars.WorkingDir, "LGPO_30", "LGPO.exe"));
            #endregion


            #region Xbox scheduled task

            bool XblGameSaveTaskResult;

            var XblGameSaveTaskResultObject = TaskSchedulerHelper.Get(
                "XblGameSaveTask",
                @"\Microsoft\XblGameSave\",
                TaskSchedulerHelper.OutputType.Boolean
            );

            // Convert to boolean
            XblGameSaveTaskResult = Convert.ToBoolean(XblGameSaveTaskResultObject, CultureInfo.InvariantCulture);

            if (XblGameSaveTaskResult)
            {
                Logger.LogMessage("Re-enables the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines", LogTypeIntel.Information);
                ProcessStarter.RunCommand("schtasks.exe", @"/Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable");
            }
            else
            {
                Logger.LogMessage("XblGameSave scheduled task couldn't be found in the task scheduler.", LogTypeIntel.Information);
            }
            #endregion


            #region DEP
            Logger.LogMessage("Setting Data Execution Prevention (DEP) back to its default value", LogTypeIntel.Information);
            _ = PowerShellExecutor.ExecuteScript(@"Set-BcdElement -Element 'nx' -Type 'Integer' -Value '0'");
            #endregion


            #region Fast MSFT Driver Block list task
            Logger.LogMessage("Removing the scheduled task that keeps the Microsoft recommended driver block rules updated", LogTypeIntel.Information);

            // Deleting the MSFT Driver Block list update Scheduled task if it exists
            _ = TaskSchedulerHelper.Delete("MSFT Driver Block list update", @"\MSFT Driver Block list update\", "MSFT Driver Block list update");

            #endregion


            #region Custom event viewer views

            // Defining the directory path to the Harden Windows Security's event viewer custom views
            string directoryPath = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive")!, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script");

            // Check if the directory exists
            if (Directory.Exists(directoryPath))
            {
                // Remove the directory and its contents recursively
                Directory.Delete(directoryPath, true);
            }

            #endregion


            #region Firewall

            _ = PowerShellExecutor.ExecuteScript("""
# Enables Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles
foreach ($FirewallRule in Get-NetFirewallRule) {
    if ($FirewallRule.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302' -and $FirewallRule.Direction -eq 'inbound') {
        foreach ($Item in $FirewallRule) {
            Enable-NetFirewallRule -DisplayName $Item.DisplayName
        }
    }
}
""");

            #endregion


            Logger.LogMessage("""Disabling auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category""", LogTypeIntel.Information);
            ProcessStarter.RunCommand("auditpol", "/set /subcategory:\"{0CCE921C-69AE-11D9-BED3-505054503030}\" /success:disable /failure:disable");

        }


        /// <summary>
        /// Removes the Country IP Blocking Firewall Rules
        /// These rules are normally removed with the rest of the group policies when the group policy directory is removed
        /// but this method is only used for when only the firewall rules need to be removed
        /// </summary>
        public static void RemoveCountryIPBlockingFirewallRules()
        {
            Logger.LogMessage("Removing the country IP blocking firewall rules only", LogTypeIntel.Information);

            FirewallHelper.BlockIPAddressListsInGroupPolicy("OFAC Sanctioned Countries IP range blocking", null, false);

            FirewallHelper.BlockIPAddressListsInGroupPolicy("State Sponsors of Terrorism IP range blocking", null, false);

            // Refresh the group policies to apply the changes instantly
            ProcessStarter.RunCommand("GPUpdate.exe", "/force");

        }


        /// <summary>
        /// Removes the process mitigations that were applied during protection from the system
        /// </summary>
        /// <exception cref="Exception"></exception>
        public static void RemoveExploitMitigations()
        {
            Logger.LogMessage("Removing the Process Mitigations / Exploit Protection settings", LogTypeIntel.Information);

            // Disable Mandatory ASLR
            // Define the PowerShell command to execute
            string command = "Set-ProcessMitigation -System -Disable ForceRelocateImages";
            _ = PowerShellExecutor.ExecuteScript(command);


            // Only remove the mitigations that are allowed to be removed
            // It is important for any executable whose name is mentioned as a key in "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" by default in a clean Windows installation, to have the RemovalAllowed property of ALL OF ITS MITIGATIONS defined in the Process Mitigations CSV file set to False
            // So regardless of whether mitigations were added by the module, only remove mitigations for processes whose names do not exist in that registry location by default, this will prevent from removing any possible built-in default mitigations
            // The following removals only affect the registry keys, they do not alter the mitigations defined in Microsoft Defender GUI
            List<ProcessMitigationsParser.ProcessMitigationsRecords> processMitigations = [.. GlobalVars.ProcessMitigations.Where(mitigation => mitigation.RemovalAllowed)];

            // Group the filtered mitigations by ProgramName
            List<IGrouping<string?, ProcessMitigationsParser.ProcessMitigationsRecords>> groupedMitigations = [.. processMitigations.GroupBy(mitigation => mitigation.ProgramName)];

            // Get all of the currently available mitigations from the registry which are executable names
            List<string>? allAvailableMitigations = Registry.LocalMachine
                .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")?
                .GetSubKeyNames()
                .ToList();

            // Loop through each group and remove corresponding registry keys
            foreach (var group in groupedMitigations)
            {
                if (allAvailableMitigations is not null && allAvailableMitigations.Contains(group.Key!))
                {
                    Registry.LocalMachine.DeleteSubKeyTree(
                        $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{group.Key}",

                        // do not to throw an exception if the specified subkey does not exist. Instead, simply proceed without raising an error.
                        throwOnMissingSubKey: false
                    );
                }
            }
        }

        /// <summary>
        /// Removes the CI Policies deployed during protection
        /// </summary>
        /// <param name="DownloadsDefenseMeasures"></param>
        /// <param name="DangerousScriptHostsBlocking"></param>
        public static void RemoveAppControlPolicies(bool DownloadsDefenseMeasures, bool DangerousScriptHostsBlocking)
        {
            // Run the CiTool and retrieve a list of base policies
            List<CiPolicyInfo> policies = CiToolRunner.RunCiTool(CiToolRunner.Options, SystemPolicies: false, BasePolicies: true, SupplementalPolicies: false);

            if (DownloadsDefenseMeasures)
            {
                // loop over all policies that currently exist on the disk and can be removed
                foreach (CiPolicyInfo item in policies.Where(policy => policy.IsOnDisk))
                {
                    // find the policy with the right name
                    if (string.Equals(item.FriendlyName, "Downloads-Defense-Measures", StringComparison.OrdinalIgnoreCase))
                    {

                        Logger.LogMessage("Removing the Downloads-Defense-Measures AppControl policy", LogTypeIntel.Information);

                        // remove the policy
                        CiToolRunner.RemovePolicy(item.PolicyID!);
                    }
                }
            }

            if (DangerousScriptHostsBlocking)
            {
                // loop over all policies that currently exist on the disk and can be removed
                foreach (CiPolicyInfo item in policies.Where(policy => policy.IsOnDisk))
                {
                    // find the policy with the right name
                    if (string.Equals(item.FriendlyName, "Dangerous-Script-Hosts-Blocking", StringComparison.OrdinalIgnoreCase))
                    {
                        Logger.LogMessage("Removing the Dangerous-Script-Hosts-Blocking AppControl policy", LogTypeIntel.Information);

                        // remove the policy
                        CiToolRunner.RemovePolicy(item.PolicyID!);
                    }
                }
            }
        }
    }
