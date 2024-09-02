using System;
using System.Management;
using System.IO;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// Class to handle Controlled Folder Access allowed applications
    /// Mostly for adding some system executables or Pwh.exe to the list during the module's operation
    /// </summary>
    public class ControlledFolderAccessHandler
    {

        /// <summary>
        /// Set the Controlled Folder Access allowed applications
        /// needs arrays
        /// </summary>
        /// <param name="applications"></param>
        public static void Set(string[] applications)
        {
            using (var managementClass = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null))
            {
                ManagementBaseObject inParams = managementClass.GetMethodParameters("Set");
                inParams["ControlledFolderAccessAllowedApplications"] = applications;

                managementClass.InvokeMethod("Set", inParams, null);
            }
        }

        /// <summary>
        /// Add applications to the Controlled Folder Access allowed applications list
        /// needs arrays
        /// Unlike Set method, it doesn't remove the existing applications
        /// </summary>
        /// <param name="applications"></param>
        public static void Add(string[] applications)
        {
            using (var managementClass = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null))
            {
                ManagementBaseObject inParams = managementClass.GetMethodParameters("Add");
                inParams["ControlledFolderAccessAllowedApplications"] = applications;

                managementClass.InvokeMethod("Add", inParams, null);
            }
        }

        /// <summary>
        /// Remove applications from the Controlled Folder Access allowed applications list
        /// needs arrays
        /// </summary>
        /// <param name="applications"></param>
        public static void Remove(string[] applications)
        {
            using (var managementClass = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null))
            {
                ManagementBaseObject inParams = managementClass.GetMethodParameters("Remove");
                inParams["ControlledFolderAccessAllowedApplications"] = applications;

                managementClass.InvokeMethod("Remove", inParams, null);
            }
        }

        /// <summary>
        /// Backup the current Controlled Folder Access allowed applications list and add PowerShell executables to it
        /// plus powercfg.exe
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        public static void Start()
        {
            // Make sure the user as Admin privileges
            if (HardenWindowsSecurity.UserPrivCheck.IsAdmin())
            {

                HardenWindowsSecurity.Logger.LogMessage("Backing up the current Controlled Folder Access allowed apps list in order to restore them at the end", LogTypeIntel.Information);

                // doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
                // no user customization will be affected
                HardenWindowsSecurity.GlobalVars.CFABackup = HardenWindowsSecurity.MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications;

                HardenWindowsSecurity.Logger.LogMessage("Temporarily adding the currently running PowerShell executables to the Controlled Folder Access allowed apps list", LogTypeIntel.Information);

                string[]? psExePaths = null;

                if (HardenWindowsSecurity.GlobalVars.PSHOME != null)
                {
                    // Get all .exe files in the PSHOME directory
                    psExePaths = Directory.GetFiles(HardenWindowsSecurity.GlobalVars.PSHOME, "*.exe");
                }

                // Get the powercfg.exe path
                string? systemDrive = Environment.GetEnvironmentVariable("SystemDrive");
                if (string.IsNullOrEmpty(systemDrive))
                {
                    throw new InvalidOperationException("SystemDrive environment variable is not set.");
                }

                string powercfgPath = Path.Combine(systemDrive, "Windows", "System32", "powercfg.exe");

                string[]? pwshPaths = null;

                if (psExePaths != null)
                {
                    // Combine the paths into a single string array
                    pwshPaths = psExePaths.Concat(new string[] { powercfgPath }).ToArray();
                }

                if (pwshPaths != null)
                {
                    // doing this so that the module can run without interruption. This change is reverted at the end.
                    // Adding powercfg.exe so Controlled Folder Access won't complain about it in BitLocker category when setting hibernate file size to full
                    HardenWindowsSecurity.ControlledFolderAccessHandler.Add(applications: pwshPaths);
                }
            }
        }

        /// <summary>
        /// Restore the original Controlled Folder Access allowed applications list
        /// </summary>
        public static void Reset()
        {

            // Make sure the user as Admin privileges
            if (HardenWindowsSecurity.UserPrivCheck.IsAdmin())
            {

                // restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
                // they will be restored as well, so user customization will remain intact
                if (HardenWindowsSecurity.GlobalVars.CFABackup != null && HardenWindowsSecurity.GlobalVars.CFABackup.Length > 0)
                {
                    HardenWindowsSecurity.Logger.LogMessage("Restoring the original Controlled Folder Access allowed apps list", LogTypeIntel.Information);
                    HardenWindowsSecurity.ControlledFolderAccessHandler.Set(applications: HardenWindowsSecurity.GlobalVars.CFABackup);
                }
                else
                {
                    // If there was nothing to backup prior to adding the executables then clear the current list that contains the executables by removing everything it contains
                    HardenWindowsSecurity.ControlledFolderAccessHandler.Remove(HardenWindowsSecurity.MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications);
                }
            }
        }
    }
}
