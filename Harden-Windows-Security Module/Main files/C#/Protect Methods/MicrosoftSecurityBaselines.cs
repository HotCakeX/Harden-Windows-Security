using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftSecurityBaselines
    {
        /// <summary>
        /// Runs the Microsoft Security Baseline category
        /// </summary>
        /// <exception cref="Exception"></exception>
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.MicrosoftSecurityBaselinePath is null)
            {
                throw new InvalidOperationException("The path to the Microsoft Security Baselines has not been set.");
            }

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            ChangePSConsoleTitle.Set("🔐 Security Baselines");

            HardenWindowsSecurity.Logger.LogMessage("Applying the Microsoft Security Baselines", LogTypeIntel.Information);
            HardenWindowsSecurity.Logger.LogMessage("Running the official PowerShell script included in the Microsoft Security Baseline file downloaded from Microsoft servers", LogTypeIntel.Information);

            // Define the path to the script
            string baselineScriptPath = Path.Combine(
                HardenWindowsSecurity.GlobalVars.MicrosoftSecurityBaselinePath,
                "Scripts",
                "Baseline-LocalInstall.ps1"
            );

            // Get the directory of the script
            string scriptDirectory = Path.GetDirectoryName(baselineScriptPath)!;

            // Set up the PowerShell command to be executed
            string Command = $"""
Set-Location -Path "{scriptDirectory}"; .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>&1
""";

            _ = PowerShellExecutor.ExecuteScript(Command, false, true);
        }
    }
}
