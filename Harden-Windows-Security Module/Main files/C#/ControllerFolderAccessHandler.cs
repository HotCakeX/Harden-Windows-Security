using System;
using System.Management;
using System.IO;
using System.Linq;

namespace HardeningModule
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

        public static void Start()
        {
            // Make sure the user as Admin privileges
            if (HardeningModule.UserPrivCheck.IsAdmin())
            {

                Console.WriteLine("Backing up the current Controlled Folder Access allowed apps list in order to restore them at the end");

                // doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
                // no user customization will be affected
                HardeningModule.GlobalVars.CFABackup = HardeningModule.MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications;

                Console.WriteLine("Temporarily adding the currently running PowerShell executables to the Controlled Folder Access allowed apps list");

                // Get all .exe files in the PSHOME directory
                string[] psExePaths = Directory.GetFiles(HardeningModule.GlobalVars.PSHOME, "*.exe");

                // Get the powercfg.exe path
                string systemDrive = Environment.GetEnvironmentVariable("SystemDrive");
                if (string.IsNullOrEmpty(systemDrive))
                {
                    throw new InvalidOperationException("SystemDrive environment variable is not set.");
                }

                string powercfgPath = Path.Combine(systemDrive, "Windows", "System32", "powercfg.exe");


                // Combine the paths into a single string array
                string[] pwshPaths = psExePaths.Concat(new string[] { powercfgPath }).ToArray();

                // doing this so that the module can run without interruption. This change is reverted at the end.
                // Adding powercfg.exe so Controlled Folder Access won't complain about it in BitLocker category when setting hibernate file size to full
                HardeningModule.ControlledFolderAccessHandler.Add(applications: pwshPaths);
            }
        }

        public static void Reset()
        {

            // Make sure the user as Admin privileges
            if (HardeningModule.UserPrivCheck.IsAdmin())
            {

                // restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
                // they will be restored as well, so user customization will remain intact
                if (HardeningModule.GlobalVars.CFABackup != null && HardeningModule.GlobalVars.CFABackup.Length > 0)
                {
                    Console.WriteLine("Restoring the original Controlled Folder Access allowed apps list");
                    HardeningModule.ControlledFolderAccessHandler.Set(applications: HardeningModule.GlobalVars.CFABackup);
                }
                else
                {
                    // If there was nothing to backup prior to adding the executables then clear the current list that contains the executables by removing everything it contains
                    HardeningModule.ControlledFolderAccessHandler.Remove(HardeningModule.MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications);
                }
            }
        }
    }
}
