using System;
using System.Diagnostics;
using System.Globalization;
using System.Threading;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class MicrosoftSecurityBaselines
    {
        /// <summary>
        /// Applies the optional overrides for the Microsoft Security Baselines
        /// </summary>
        /// <exception cref="Exception"></exception>
        public static void SecBaselines_Overrides()
        {
            if (HardenWindowsSecurity.GlobalVars.MicrosoftSecurityBaselinePath is null)
            {
                throw new InvalidOperationException("The path to the Microsoft Security Baselines has not been set.");
            }

            if (HardenWindowsSecurity.GlobalVars.path is null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            // Sleep for 1 second (1000 milliseconds)
            Thread.Sleep(1000);

            HardenWindowsSecurity.Logger.LogMessage("Applying the optional overrides", LogTypeIntel.Information);

            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Overrides for Microsoft Security Baseline", "registry.pol"), LGPORunner.FileType.POL);
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Overrides for Microsoft Security Baseline", "GptTmpl.inf"), LGPORunner.FileType.INF);

            #region Xbox Game Save Scheduled task re-enablement
            bool XblGameSaveTaskResult;

            var XblGameSaveTaskResultObject = HardenWindowsSecurity.TaskSchedulerHelper.Get(
                "XblGameSaveTask",
                @"\Microsoft\XblGameSave\",
                HardenWindowsSecurity.TaskSchedulerHelper.OutputType.Boolean
            );

            // Convert to boolean
            XblGameSaveTaskResult = Convert.ToBoolean(XblGameSaveTaskResultObject, CultureInfo.InvariantCulture);

            // Make sure the Xbox game save scheduled task exists before attempting to enable it
            if (XblGameSaveTaskResult)
            {

                HardenWindowsSecurity.Logger.LogMessage("Re-enabling the XblGameSave Standby Task that gets disabled by Microsoft Security Baselines", LogTypeIntel.Information);

                // Create a new process
                using Process process = new();

                process.StartInfo.FileName = "SCHTASKS.EXE";
                process.StartInfo.Arguments = "/Change /TN \\Microsoft\\XblGameSave\\XblGameSaveTask /Enable";

                // Set to false to display output/error in the console
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;

                // Start the process
                _ = process.Start();

                // Read the output (if any)
                string output = process.StandardOutput.ReadToEnd();
                string error = process.StandardError.ReadToEnd();

                // Wait for the process to exit
                process.WaitForExit();

                // Check for errors
                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException($"Process failed with exit code {process.ExitCode}: {error}");
                }

                HardenWindowsSecurity.Logger.LogMessage(output, LogTypeIntel.Information);

            }
            else
            {
                HardenWindowsSecurity.Logger.LogMessage("XblGameSave scheduled task couldn't be found in the task scheduler.", LogTypeIntel.Information);
            }
            #endregion
        }
    }
}
