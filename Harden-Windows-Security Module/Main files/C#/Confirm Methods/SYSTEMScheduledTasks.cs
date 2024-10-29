using System;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class SYSTEMScheduledTasks
    {
        public static void Invoke()
        {
            Logger.LogMessage("Collecting Intune applied policy details from the System", LogTypeIntel.Information);

            // Path to the PowerShell script
            string scriptPath = Path.Combine(GlobalVars.path!, "Shared", "SYSTEMInfoGathering.ps1");

            // Load the PowerShell script into a string
            string script = File.ReadAllText(scriptPath);

            // Replace the BaseDirectory placeholder with the actual value
            script = script.Replace("[System.String]$BaseDirectory = [HardenWindowsSecurity.GlobalVars]::WorkingDir", $"[System.String]$BaseDirectory = '{GlobalVars.WorkingDir}'", StringComparison.OrdinalIgnoreCase);

            // Run the PowerShell script
            _ = PowerShellExecutor.ExecuteScript(script);
        }
    }
}
