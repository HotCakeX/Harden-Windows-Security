using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class UserAccountControl
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the User Account Control category");
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "User Account Control UAC Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
}
