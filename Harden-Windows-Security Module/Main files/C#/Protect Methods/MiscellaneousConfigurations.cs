using System;
using System.Collections.Generic;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MiscellaneousConfigurations
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }
            if (HardenWindowsSecurity.GlobalVars.RegistryCSVItems is null)
            {
                throw new System.ArgumentNullException("GlobalVars.RegistryCSVItems cannot be null.");
            }

            ChangePSConsoleTitle.Set("🥌 Miscellaneous");

            HardenWindowsSecurity.Logger.LogMessage("Running the Miscellaneous Configurations category", LogTypeIntel.Information);

            HardenWindowsSecurity.Logger.LogMessage("Applying the Miscellaneous Configurations registry settings", LogTypeIntel.Information);
#nullable disable
            foreach (HardeningRegistryKeys.CsvRecord Item in (HardenWindowsSecurity.GlobalVars.RegistryCSVItems))
            {
                if (string.Equals(Item.Category, "Miscellaneous", StringComparison.OrdinalIgnoreCase))
                {
                    HardenWindowsSecurity.RegistryEditor.EditRegistry(Item.Path, Item.Key, Item.Value, Item.Type, Item.Action);
                }
            }
#nullable enable

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "registry.pol"), LGPORunner.FileType.POL);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Miscellaneous Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);

            HardenWindowsSecurity.Logger.LogMessage("""Adding all Windows users to the "Hyper-V Administrators" security group to be able to use Hyper-V and Windows Sandbox""", LogTypeIntel.Information);
            List<HardenWindowsSecurity.LocalUser> AllLocalUsers = HardenWindowsSecurity.LocalUserRetriever.Get();

            foreach (HardenWindowsSecurity.LocalUser user in AllLocalUsers)
            {
                // If the user has SID and the user is enabled
                if (user.SID is not null && user.Enabled)
                {
                    HardenWindowsSecurity.LocalGroupMember.Add(user.SID, "S-1-5-32-578");
                }
            }

            // Makes sure auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category is enabled, doesn't touch affect any other sub-category
            // For tracking Lock screen unlocks and locks
            // auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
            // Using GUID

            HardenWindowsSecurity.Logger.LogMessage("""Enabling auditing for the "Other Logon/Logoff Events" subcategory under the Logon/Logoff category""", LogTypeIntel.Information);

            HardenWindowsSecurity.RunCommandLineCommands.Run("auditpol", "/set /subcategory:\"{0CCE921C-69AE-11D9-BED3-505054503030}\" /success:enable /failure:enable");

            // Query all Audits status
            // auditpol /get /category:*
            // Get the list of SubCategories and their associated GUIDs
            // auditpol /list /subcategory:* /r

            // Event Viewer custom views are saved in "$env:SystemDrive\ProgramData\Microsoft\Event Viewer\Views". files in there can be backed up and restored on new Windows installations.
            string? systemDrive = Environment.GetEnvironmentVariable("SystemDrive") ?? throw new System.ArgumentNullException("SystemDrive cannot be null.");

            // Create the directory if it doesn't exist
            if (!System.IO.Directory.Exists(Path.Combine(systemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script")))
            {
                _ = System.IO.Directory.CreateDirectory(Path.Combine(systemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script"));
            }

            foreach (string File in System.IO.Directory.GetFiles(Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "EventViewerCustomViews")))
            {
                System.IO.File.Copy(File, Path.Combine(systemDrive, "ProgramData", "Microsoft", "Event Viewer", "Views", "Hardening Script", System.IO.Path.GetFileName(File)), true);
            }

            SSHConfigurations.SecureMACs();
        }
    }
}
