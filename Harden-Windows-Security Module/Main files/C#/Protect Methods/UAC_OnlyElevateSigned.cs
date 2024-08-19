using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class UserAccountControl
    {
        public static void UAC_OnlyElevateSigned()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Applying the Only elevate executables that are signed and validated policy");
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "User Account Control UAC Policies", "Only elevate executables that are signed and validated" , "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
}
