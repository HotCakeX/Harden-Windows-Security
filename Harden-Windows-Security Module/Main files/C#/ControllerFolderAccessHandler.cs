using System;
using System.Management;

namespace HardeningModule
{
    /// <summary>
    /// Class to handle Controlled Folder Access allowed applications
    /// Mostly for adding some system executables or Pwh.exe to the list during the module's operation
    /// </summary>
    public class ControllerFolderAccessHandler
    {

        /// <summary>
        /// Set the Controlled Folder Access allowed applications
        /// needs arrays
        /// Can be used like this to act as a wildcard remove: [HardeningModule.ControllerFolderAccessHandler]::Set('')
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
    }
}
