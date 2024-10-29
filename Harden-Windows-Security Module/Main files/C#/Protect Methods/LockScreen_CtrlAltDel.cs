using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class LockScreen
    {
        public static void LockScreen_CtrlAltDel()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Applying the Enable CTRL + ALT + DEL policy", LogTypeIntel.Information);
            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "Enable CTRL + ALT + DEL", "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
}
