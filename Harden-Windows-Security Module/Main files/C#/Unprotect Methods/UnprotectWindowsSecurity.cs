using System;
using System.IO;
using System.Net.Http;
using System.IO.Compression;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
    public class UnprotectWindowsSecurity
    {
        /// <summary>
        /// Performs the main tasks for removing protections from Windows that were applied during the protection phase
        /// </summary>
        public static void Unprotect()
        {

            #region
            HardenWindowsSecurity.Logger.LogMessage("Removing all of the group policies from the system.");

            string GroupPolicyDirectoryLocation = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "GroupPolicy");

            if (Directory.Exists(GroupPolicyDirectoryLocation))
            {
                Directory.Delete(GroupPolicyDirectoryLocation, true);
            }
            #endregion


            #region
            HardenWindowsSecurity.Logger.LogMessage("Deleting all the registry keys created during protection.");

            foreach (var Item in HardenWindowsSecurity.GlobalVars.RegistryCSVItems!)
            {
                HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path!, Item.Key!, Item.Value!, Item.Type!, "Delete");
            }

            // To completely remove the Edge policy since only its sub-keys are removed by the command above
            using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Edge", writable: true))
            {
                if (key != null)
                {
                    // Delete the specified subkey and its contents
                    key.DeleteSubKeyTree("TLSCipherSuiteDenyList", throwOnMissingSubKey: false);
                }
            }

            //Set a tattooed Group policy for Svchost.exe process mitigations back to disabled state
            HardenWindowsSecurity.RegistryEditor.EditRegistry(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SCMConfig", "EnableSvchostMitigationPolicy", "0", "DWORD", "AddOrModify");

            #endregion


            #region
            HardenWindowsSecurity.Logger.LogMessage("Reverting the advanced protections in the Microsoft Defender.");

            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("AllowSwitchToAsyncInspection", false);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("OobeEnableRtpAndSigUpdate", false);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("IntelTDTEnabled", false);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("DisableRestorePoint", true);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("PerformanceModeStatus", 0);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("EnableConvertWarnToBlock", false);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("BruteForceProtectionAggressiveness", 0);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("BruteForceProtectionConfiguredState", 0);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("RemoteEncryptionProtectionAggressiveness", 0);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<byte>("RemoteEncryptionProtectionConfiguredState", 0);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("BruteForceProtectionLocalNetworkBlocking", false);
            HardenWindowsSecurity.MpComputerStatusHelper.SetMpComputerStatus<bool>("EnableEcsConfiguration", false);
            #endregion


            #region
            HardenWindowsSecurity.Logger.LogMessage("Restoring the default Security group policies");

            // Defining the URL to download the LGPO.zip from
            string LgpoURL = "https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip";

            // Defining the path where the ZIP file will be saved
            string zipFilePath = Path.Combine(GlobalVars.WorkingDir, "LGPO.zip");

            HardenWindowsSecurity.Logger.LogMessage("Downloading the LGPO.exe from the Microsoft servers");

            // Download the ZIP file from the URL using HttpClient
            using (HttpClient client = new HttpClient())
            {
                // Download the file as a byte array synchronously
                byte[] zipFileBytes = client.GetByteArrayAsync(LgpoURL).Result;

                // Save the byte array to a file
                File.WriteAllBytes(zipFilePath, zipFileBytes);
            }

            // Extract the ZIP file
            ZipFile.ExtractToDirectory(zipFilePath, GlobalVars.WorkingDir, true);

            // Apply the default security policy on the system
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path!, "Resources", "Default Security Policy.inf"), LGPORunner.FileType.INF, Path.Combine(GlobalVars.WorkingDir, "LGPO_30", "LGPO.exe"));
            #endregion


            #region
            HardenWindowsSecurity.Logger.LogMessage("Re-enables the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines");
            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(@"SCHTASKS.EXE /Change /TN \Microsoft\XblGameSave\XblGameSaveTask /Enable");
            #endregion


            #region
            HardenWindowsSecurity.Logger.LogMessage("Setting Data Execution Prevention (DEP) back to its default value");
            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(@"Set-BcdElement -Element 'nx' -Type 'Integer' -Value '0'");
            #endregion


            #region
            HardenWindowsSecurity.Logger.LogMessage("Removing the scheduled task that keeps the Microsoft recommended driver block rules updated");

            // If the task exists, delete it
            if (Convert.ToBoolean(HardenWindowsSecurity.TaskSchedulerHelper.Get("MSFT Driver Block list update", @"\MSFT Driver Block list update\", TaskSchedulerHelper.OutputType.Boolean), CultureInfo.InvariantCulture))
            {
                HardenWindowsSecurity.PowerShellExecutor.ExecuteScript("""
schtasks.exe /Delete /TN "\MSFT Driver Block list update\MSFT Driver Block list update" /F # Delete task
schtasks.exe /Delete /TN "MSFT Driver Block list update" /F *>$null # Delete task path
""");
            }

            #endregion


            #region

            // Defining the directory path to the Harden Windows Security's event viewer custom views
            string directoryPath = Path.Combine(Environment.GetEnvironmentVariable("SystemDrive")!, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script");

            // Check if the directory exists
            if (Directory.Exists(directoryPath))
            {
                // Remove the directory and its contents recursively
                Directory.Delete(directoryPath, true);
            }

            #endregion

            #region

            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript("""
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

        }


        /// <summary>
        /// Removes the Country IP Blocking Firewall Rules
        /// These rules are normally removed with the rest of the group policies when the group policy directory is removed
        /// but this method is only used for when only the firewall rules need to be removed
        /// </summary>
        public static void RemoveCountryIPBlockingFirewallRules()
        {
            HardenWindowsSecurity.Logger.LogMessage("Removing the country IP blocking firewall rules only");

            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript("""
# Normally these are removed when all group policies are removed, but in case only the firewall rules are removed
Remove-NetFirewallRule -DisplayName 'OFAC Sanctioned Countries IP range blocking' -PolicyStore localhost -ErrorAction SilentlyContinue
Remove-NetFirewallRule -DisplayName 'State Sponsors of Terrorism IP range blocking' -PolicyStore localhost -ErrorAction SilentlyContinue
Start-Process -FilePath GPUpdate.exe -ArgumentList '/force' -NoNewWindow
""");
        }


        /// <summary>
        /// Removes the process mitigations that were applied during protection from the system
        /// </summary>
        /// <exception cref="Exception"></exception>
        public static void RemoveExploitMitigations()
        {
            HardenWindowsSecurity.Logger.LogMessage("Removing the Process Mitigations / Exploit Protection settings");

            // Disable Mandatory ASLR
            // Define the PowerShell command to execute
            string command = "Set-ProcessMitigation -System -Disable ForceRelocateImages";
            HardenWindowsSecurity.PowerShellExecutor.ExecuteScript(command);


            if (HardenWindowsSecurity.GlobalVars.ProcessMitigations == null)
            {
                throw new Exception("GlobalVars.ProcessMitigations is null.");
            }

            // Only remove the mitigations that are allowed to be removed
            // It is important for any executable whose name is mentioned as a key in "Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" by default in a clean Windows installation, to have its RemovalAllowed property in the Process Mitigations CSV file set to False
            // So regardless of whether mitigations were added by the module, only remove mitigations for processes whose names do not exist in that registry location by default, this will prevent from removing any possible built-in default mitigations
            List<HardenWindowsSecurity.ProcessMitigationsParser.ProcessMitigationsRecords> processMitigations = HardenWindowsSecurity.GlobalVars.ProcessMitigations
                .Where(mitigation => mitigation.RemovalAllowed)
                .ToList();

            // Group the filtered mitigations by ProgramName
            List<IGrouping<string?, HardenWindowsSecurity.ProcessMitigationsParser.ProcessMitigationsRecords>>? groupedMitigations = processMitigations
                .GroupBy(mitigation => mitigation.ProgramName)
                .ToList();

            // Get all of the currently available mitigations from the registry which are executable names
            List<string>? allAvailableMitigations = Registry.LocalMachine
                .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")?
                .GetSubKeyNames()
                .ToList();

            // Loop through each group and remove corresponding registry keys
            foreach (var group in groupedMitigations)
            {
                if (allAvailableMitigations != null)
                {
                    if (allAvailableMitigations.Contains(group.Key!))
                    {
                        Registry.LocalMachine.DeleteSubKeyTree(
                            $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{group.Key}",

                            // do not to throw an exception if the specified subkey does not exist. Instead, simply proceed without raising an error.
                            throwOnMissingSubKey: false
                        );
                    }
                }
            }
        }

        /// <summary>
        /// Removes the CI Policies deployed during protection
        /// </summary>
        /// <param name="DownloadsDefenseMeasures"></param>
        /// <param name="DangerousScriptHostsBlocking"></param>
        public static void RemoveWDACPolicies(bool DownloadsDefenseMeasures, bool DangerousScriptHostsBlocking)
        {
            // Run the CiTool and retrieve a list of base policies
            List<CiPolicyInfo> policies = CiToolRunner.RunCiTool(SystemPolicies: false, BasePolicies: true, SupplementalPolicies: false);

            if (DownloadsDefenseMeasures == true)
            {
                // loop over all policies that currently exist on the disk and can be removed
                foreach (CiPolicyInfo item in policies.Where(policy => policy.IsOnDisk == true))
                {
                    // find the policy with the right name
                    if (string.Equals(item.FriendlyName, "Downloads-Defense-Measures", StringComparison.OrdinalIgnoreCase))
                    {

                        HardenWindowsSecurity.Logger.LogMessage("Removing the Downloads-Defense-Measures WDAC policy");

                        // remove the policy
                        HardenWindowsSecurity.CiToolRunner.RemovePolicy(item.PolicyID!);
                    }
                }
            }

            if (DangerousScriptHostsBlocking == true)
            {
                // loop over all policies that currently exist on the disk and can be removed
                foreach (CiPolicyInfo item in policies.Where(policy => policy.IsOnDisk == true))
                {
                    // find the policy with the right name
                    if (string.Equals(item.FriendlyName, "Dangerous-Script-Hosts-Blocking", StringComparison.OrdinalIgnoreCase))
                    {
                        HardenWindowsSecurity.Logger.LogMessage("Removing the Dangerous-Script-Hosts-Blocking WDAC policy");

                        // remove the policy
                        HardenWindowsSecurity.CiToolRunner.RemovePolicy(item.PolicyID!);
                    }
                }
            }
        }
    }
}
