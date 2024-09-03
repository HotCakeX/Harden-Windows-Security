using System;
using System.Diagnostics;
using System.IO;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class MicrosoftSecurityBaselines
    {
        /// <summary>
        /// Runs the Microsoft Security Baseline category
        /// </summary>
        /// <exception cref="Exception"></exception>
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.MicrosoftSecurityBaselinePath == null)
            {
                throw new Exception("The path to the Microsoft Security Baselines has not been set.");
            }

            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

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
            string arguments = $"""
-NoProfile -ExecutionPolicy Bypass -Command "Set-Location -Path \"{scriptDirectory}\"; .\Baseline-LocalInstall.ps1 -Win11NonDomainJoined 4>&1"
""";

            // Create the process start info
            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            // Start the process
            using (var process = Process.Start(startInfo))
            {
                // Capture the output and error messages
                string output = process!.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                // Wait for the process to exit
                process.WaitForExit();

                // Write non-error output to the console
                if (!string.IsNullOrEmpty(output))
                {
                    HardenWindowsSecurity.Logger.LogMessage(output, LogTypeIntel.Information);
                }

                // If there was an error, throw it
                if (process.ExitCode != 0 || !string.IsNullOrEmpty(error))
                {
                    throw new Exception(error);
                }
            }
        }
    }
}
