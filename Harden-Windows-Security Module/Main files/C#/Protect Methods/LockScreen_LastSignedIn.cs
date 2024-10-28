using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class LockScreen
    {

        public static void LockScreen_LastSignedIn()
        {

            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            Logger.LogMessage("Applying the Don't display last signed-in policy", LogTypeIntel.Information);
            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "Don't display last signed-in", "GptTmpl.inf"), LGPORunner.FileType.INF);

        }
    }
}
