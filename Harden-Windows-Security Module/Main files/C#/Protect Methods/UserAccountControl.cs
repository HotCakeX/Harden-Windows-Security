using System;
using System.IO;

namespace HardenWindowsSecurity;

    public static partial class UserAccountControl
    {
        /// <summary>
        /// Runs the User Account Control (UAC) hardening category
        /// </summary>
        /// <exception cref="ArgumentNullException"></exception>
        public static void Invoke()
        {
            if (GlobalVars.path is null)
            {
                throw new ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("💎 UAC");

            Logger.LogMessage("Running the User Account Control category", LogTypeIntel.Information);
            LGPORunner.RunLGPOCommand(Path.Combine(GlobalVars.path, "Resources", "Security-Baselines-X", "User Account Control UAC Policies", "GptTmpl.inf"), LGPORunner.FileType.INF);
        }
    }
