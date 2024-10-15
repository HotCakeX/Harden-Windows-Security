using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class InvokeConfirmation
    {
        /// <summary>
        /// This method will perform the system compliance checking and verification
        /// </summary>
        /// <param name="Categories"></param>
        public static void Invoke(string[] Categories)
        {
            HardenWindowsSecurity.Logger.LogMessage("Collecting Intune applied policy details from the System", LogTypeIntel.Information);

            HardenWindowsSecurity.Logger.LogMessage("Controlled Folder Access Handling", LogTypeIntel.Information);
            HardenWindowsSecurity.ControlledFolderAccessHandler.Start();

            // Give the Defender internals time to process the updated exclusions list
            Thread.Sleep(5000);

            HardenWindowsSecurity.Logger.LogMessage("Collecting any possible Intune/MDM policies", LogTypeIntel.Information);
            HardenWindowsSecurity.SYSTEMScheduledTasks.Invoke();

            // Collect the JSON File Paths
            string MDM_Firewall_DomainProfile02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Firewall_DomainProfile02.json");
            string MDM_Firewall_PrivateProfile02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Firewall_PrivateProfile02.json");
            string MDM_Firewall_PublicProfile02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Firewall_PublicProfile02.json");
            string MDM_Policy_Result01_Update02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Policy_Result01_Update02.json");
            string MDM_Policy_Result01_System02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Policy_Result01_System02.json");


            // Wait until all files are created, this is necessary because sometimes it takes a second or two for the scheduled task to create the files
            // Initialize a stopwatch to track the elapsed time so we don't wait indefinitely
            Stopwatch stopwatch = Stopwatch.StartNew();

            while (true)
            {
                try
                {
                    // Check if all files exist
                    if (File.Exists(MDM_Firewall_DomainProfile02_Path) &&
                        File.Exists(MDM_Firewall_PrivateProfile02_Path) &&
                        File.Exists(MDM_Firewall_PublicProfile02_Path) &&
                        File.Exists(MDM_Policy_Result01_Update02_Path) &&
                        File.Exists(MDM_Policy_Result01_System02_Path))
                    {
                        break; // Exit the loop if all files exist
                    }
                }
                catch (IOException)
                {
                    // Ignore IOException and continue waiting
                    // Because the scheduled task will probably be accessing the file at the same time as well
                }

                // Check if the timeout has been exceeded
                if (stopwatch.ElapsedMilliseconds > 10000) // 10 seconds in milliseconds
                {
                    throw new TimeoutException("Timeout exceeded while waiting for the MDM policy files to be created.");
                }

                // Sleep for a short period before checking again
                Thread.Sleep(500);
            }

            // Parse the JSON Files and store the results in global variables
            HardenWindowsSecurity.GlobalVars.MDM_Firewall_DomainProfile02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Firewall_DomainProfile02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Firewall_PrivateProfile02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Firewall_PrivateProfile02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Firewall_PublicProfile02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Firewall_PublicProfile02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Policy_Result01_Update02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Policy_Result01_Update02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Policy_Result01_System02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Policy_Result01_System02_Path);

            HardenWindowsSecurity.Logger.LogMessage("Verifying the security settings", LogTypeIntel.Information);
            HardenWindowsSecurity.ConfirmSystemComplianceMethods.OrchestrateComplianceChecks(Categories);

        }
    }
}
