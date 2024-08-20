using System;
using System.IO;
using System.Globalization;
using System.Management.Automation;
using System.Security.Principal;
using System.Threading;

#nullable enable

namespace HardenWindowsSecurity
{
    public class InvokeConfirmation
    {
        /// <summary>
        /// This method will perform the system compliance checking and verification
        /// </summary>
        /// <param name="Categories"></param>
        public static void Invoke(string[] Categories)
        {
            HardenWindowsSecurity.Logger.LogMessage("Collecting Intune applied policy details from the System");

            HardenWindowsSecurity.Logger.LogMessage("Controlled Folder Access Handling");
            HardenWindowsSecurity.ControlledFolderAccessHandler.Start();

            // Give the Defender internals time to process the updated exclusions list
            Thread.Sleep(5000);

            HardenWindowsSecurity.Logger.LogMessage("Collecting any possible Intune/MDM policies");
            HardenWindowsSecurity.SYSTEMScheduledTasks.Invoke();

            // Collect the JSON File Paths
            string MDM_Firewall_DomainProfile02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Firewall_DomainProfile02.json");
            string MDM_Firewall_PrivateProfile02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Firewall_PrivateProfile02.json");
            string MDM_Firewall_PublicProfile02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Firewall_PublicProfile02.json");
            string MDM_Policy_Result01_Update02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Policy_Result01_Update02.json");
            string MDM_Policy_Result01_System02_Path = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.WorkingDir, "MDM_Policy_Result01_System02.json");

            // Parse the JSON Files and store the results in global variables
            HardenWindowsSecurity.GlobalVars.MDM_Firewall_DomainProfile02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Firewall_DomainProfile02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Firewall_PrivateProfile02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Firewall_PrivateProfile02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Firewall_PublicProfile02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Firewall_PublicProfile02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Policy_Result01_Update02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Policy_Result01_Update02_Path);
            HardenWindowsSecurity.GlobalVars.MDM_Policy_Result01_System02 = HardenWindowsSecurity.JsonToHashtable.ProcessJsonFile(MDM_Policy_Result01_System02_Path);

            HardenWindowsSecurity.Logger.LogMessage("Verifying the security settings");
            HardenWindowsSecurity.ConfirmSystemComplianceMethods.OrchestrateComplianceChecks(Categories);

        }
    }
}
