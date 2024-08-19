using System;
using System.IO;
using Microsoft.Win32;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class LockScreen
    {
        public static void Invoke()
        {

            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the Lock Screen category");

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "registry.pol"), LGPORunner.FileType.POL);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Lock Screen Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);

        }
    }
}
