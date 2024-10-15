using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Reflection;

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// Class to handle Controlled Folder Access allowed applications
    /// Mostly for adding some system executables or Pwh.exe to the list during the module's operation
    /// </summary>
    public class ControlledFolderAccessHandler
    {
        // To track if the Reset() method has been run
        private static bool HasResetHappenedBefore;
        // To track if the Start() method has been run
        private static bool HasBackupHappenedBefore;


        /// <summary>
        /// Set the Controlled Folder Access allowed applications
        /// needs arrays
        /// </summary>
        /// <param name="applications"></param>
        private static void Set(string[] applications)
        {
            using var managementClass = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);

            ManagementBaseObject inParams = managementClass.GetMethodParameters("Set");
            inParams["ControlledFolderAccessAllowedApplications"] = applications;

            _ = managementClass.InvokeMethod("Set", inParams, null);
        }

        /// <summary>
        /// Add applications to the Controlled Folder Access allowed applications list
        /// needs arrays
        /// Unlike Set method, it doesn't remove the existing applications
        /// </summary>
        /// <param name="applications"></param>
        private static void Add(string[] applications)
        {
            using var managementClass = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);

            ManagementBaseObject inParams = managementClass.GetMethodParameters("Add");
            inParams["ControlledFolderAccessAllowedApplications"] = applications;

            _ = managementClass.InvokeMethod("Add", inParams, null);
        }

        /// <summary>
        /// Remove applications from the Controlled Folder Access allowed applications list
        /// needs arrays
        /// </summary>
        /// <param name="applications"></param>
        private static void Remove(string[] applications)
        {
            using var managementClass = new ManagementClass(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);

            ManagementBaseObject inParams = managementClass.GetMethodParameters("Remove");
            inParams["ControlledFolderAccessAllowedApplications"] = applications;

            _ = managementClass.InvokeMethod("Remove", inParams, null);
        }

        /// <summary>
        /// Backup the current Controlled Folder Access allowed applications list and add PowerShell executables to it
        /// plus powercfg.exe
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        public static void Start()
        {
            // Make sure the user has Admin privileges
            if (UserPrivCheck.IsAdmin())
            {

                if (HasBackupHappenedBefore)
                {
                    return;
                }

                Logger.LogMessage("Backing up the current Controlled Folder Access allowed apps list in order to restore them at the end", LogTypeIntel.Information);

                // Doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
                // no user customization will be affected
                GlobalVars.CFABackup = MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications;

                Logger.LogMessage("Temporarily adding the currently running PowerShell executables to the Controlled Folder Access allowed apps list", LogTypeIntel.Information);

                // A HashSet of string to store the paths of the files that will be added to the CFA exclusions
                HashSet<string> CFAExclusionsToBeAdded = [];

                #region powercfg.exe executable
                // Get the powercfg.exe path
                string? systemDrive = Environment.GetEnvironmentVariable("SystemDrive");
                if (string.IsNullOrEmpty(systemDrive))
                {
                    throw new InvalidOperationException("SystemDrive environment variable is not set.");
                }

                string powercfgPath = Path.Combine(systemDrive, "Windows", "System32", "powercfg.exe");

                // Add the powercfg.exe path to the CFA Exclusion list
                _ = CFAExclusionsToBeAdded.Add(powercfgPath);
                #endregion

                #region PowerShell and/or standalone executable
                // If Harden Windows Security App is being executed using compiled binary, or in the context of PowerShell as a module, then this part will take care of CFA exclusion

                // Get the path of the currently executing assembly
                string? executablePath = Assembly.GetExecutingAssembly()?.Location;

                if (!string.IsNullOrWhiteSpace(executablePath))
                {
                    Logger.LogMessage("Executable Path temporarily being added to the Controlled Folder Access Exclusions: " + executablePath, LogTypeIntel.Information);

                    // Ensure the file has a .exe extension
                    if (Path.GetExtension(executablePath).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        _ = CFAExclusionsToBeAdded.Add(executablePath);
                    }
                }

                // Get the path of the current process executable
                string? executablePathExe = Process.GetCurrentProcess()?.MainModule?.FileName;

                if (!string.IsNullOrWhiteSpace(executablePathExe))
                {
                    Logger.LogMessage("Executable Path temporarily being added to the Controlled Folder Access Exclusions: " + executablePathExe, LogTypeIntel.Information);

                    // Ensure the file has a .exe extension because it could be the dll
                    if (Path.GetExtension(executablePathExe).Equals(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        _ = CFAExclusionsToBeAdded.Add(executablePathExe);
                    }
                }
                #endregion

                // Convert the HashSet to a string array
                string[] CFAExclusionsToBeAddedArray = [.. CFAExclusionsToBeAdded];

                // Adding powercfg.exe so Controlled Folder Access won't complain about it in BitLocker category when setting hibernate file size to full
                if (CFAExclusionsToBeAddedArray.Length > 0)
                {
                    // Doing this so that the module can run without interruption. This change is reverted at the end.
                    // Adding powercfg.exe so Controlled Folder Access won't complain about it in BitLocker category when setting hibernate file size to full
                    ControlledFolderAccessHandler.Add(CFAExclusionsToBeAddedArray);
                }

                // Set this to true indicating CFA exclusions backup has already happened
                HasBackupHappenedBefore = true;
            }
        }

        /// <summary>
        /// Restore the original Controlled Folder Access allowed applications list
        /// </summary>
        public static void Reset()
        {
            // Make sure the user as Admin privileges
            if (UserPrivCheck.IsAdmin())
            {
                // Since this method is called in multiple places, make sure it only runs once during app exit
                if (HasResetHappenedBefore)
                {
                    return;
                }

                // restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
                // they will be restored as well, so user customization will remain intact
                if (GlobalVars.CFABackup is not null && GlobalVars.CFABackup.Length > 0)
                {
                    Logger.LogMessage("Restoring the original Controlled Folder Access allowed apps list", LogTypeIntel.Information);
                    ControlledFolderAccessHandler.Set(applications: GlobalVars.CFABackup);
                }
                else
                {
                    // If there was nothing to backup prior to adding the executables then clear the current list that contains the executables by removing everything it contains
                    ControlledFolderAccessHandler.Remove(MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications);
                }

                // Set this to true indicating CFA exclusion reset has already happened
                HasResetHappenedBefore = true;
            }

            // Set the variable to null after being done with it so subsequent attempts of this method won't run in the same session
            GlobalVars.CFABackup = null;
        }
    }
}
